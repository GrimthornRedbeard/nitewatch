//go:build windows

package source

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/threattape/nitewatch/agent/internal/event"
)

// debugETW dumps raw ETW records (field names + values) when NITEWATCH_DEBUG_ETW
// is set. ETW property names vary across Windows builds, so this is the ground
// truth used to fix field mappings without guessing.
var debugETW = os.Getenv("NITEWATCH_DEBUG_ETW") != ""

var debugCount atomic.Int64

const debugMaxRecords = 60

// noisyTasks are high-frequency bookkeeping events that carry no security
// signal. They are skipped by the debug dump so a capture shows the records we
// actually map.
var noisyTasks = map[string]bool{
	"ThreadWorkOnBehalfUpdate": true,
	"CpuPriorityChange":        true,
	"IoPriorityChange":         true,
	"PagePriorityChange":       true,
	"OperationEnd":             true,
}

func dumpRecord(e *etw.Event) {
	if noisyTasks[e.System.Task.Name] {
		return
	}
	if n := debugCount.Add(1); n > debugMaxRecords {
		return
	}
	b, _ := json.Marshal(map[string]any{
		"provider":  e.System.Provider.Name,
		"eventID":   e.System.EventID,
		"opcode":    e.System.Opcode.Name,
		"task":      e.System.Task.Name,
		"execPID":   e.System.Execution.ProcessID,
		"eventData": e.EventData,
		"userData":  e.UserData,
	})
	log.Printf("ETW_RAW %s", b)
}

// etwProviders are the userland ETW providers the flight recorder subscribes
// to. No kernel driver is involved — all are consumable from an elevated
// userland session.
//
// Format is "name:level:eventIDs:matchAnyKeyword". Filtering here rather than
// in normalize() matters: enabling these providers wide open buries the useful
// records under a flood of ThreadWorkOnBehalfUpdate / CpuPriorityChange /
// per-IRP file events (observed on a live Win11 box: ~99% noise).
//
// Kernel-File is deliberately NOT enabled in P1 — the flight recorder only
// needs process + network + DNS, and Kernel-File is the highest-volume provider
// on the system. It comes back in P2 for ransomware-pattern detection, scoped
// to the events that actually matter.
// Each entry is tried in order and the first that enables wins, so a spec that
// a given Windows build rejects degrades to a broader one instead of killing
// the sensor. Keyword filtering (MatchAnyKeyword) is used rather than event-ID
// filter descriptors: the latter are rejected outright by some builds
// (EnableTraceEx2 -> ERROR_INVALID_PARAMETER, observed on Win11).
var etwProviders = []providerSpec{
	{
		name: "Kernel-Process",
		// Keyword 0x10 = WINEVENT_KEYWORD_PROCESS: process start/stop only,
		// excluding the CPU_PRIORITY (0x80) and WORK_ON_BEHALF (0x2000)
		// bookkeeping that otherwise dominates the stream.
		specs: []string{
			"Microsoft-Windows-Kernel-Process:0xff::0x10",
			"Microsoft-Windows-Kernel-Process",
		},
		required: false,
	},
	{
		name: "Kernel-Network",
		// All network events (v4/v6, TCP/UDP). Volume is handled by flow
		// de-duplication in the ledger rather than dropped here, so we keep
		// visibility into every destination contacted.
		specs:    []string{"Microsoft-Windows-Kernel-Network"},
		required: true, // without this there is no connection ledger at all
	},
	{
		// Kernel-File returns in P2 for ransomware and credential detection.
		// It is the highest-volume provider on the system, so normalize()
		// discards everything outside user data and secret stores immediately.
		name:     "Kernel-File",
		specs:    []string{"Microsoft-Windows-Kernel-File"},
		required: false,
	},
	{
		name:     "DNS-Client",
		specs:    []string{"Microsoft-Windows-DNS-Client"},
		required: false, // reverse DNS still names destinations without it
	},
}

// providerSpec is one logical telemetry source and its fallback ladder.
type providerSpec struct {
	name     string
	specs    []string
	required bool
}

type etwSource struct {
	session  *etw.RealTimeSession
	consumer *etw.Consumer
	cancel   context.CancelFunc
	seq      atomic.Uint64
}

// NewETWSource creates (but does not start) an ETW-backed EventSource. The
// process must run elevated; EnableProvider will fail otherwise.
func NewETWSource() (EventSource, error) {
	session := etw.NewRealTimeSession("NiteWatch")

	var enabled int
	for _, ps := range etwProviders {
		err := enableWithFallback(session, ps)
		if err == nil {
			enabled++
			continue
		}
		if ps.required {
			_ = session.Stop()
			return nil, fmt.Errorf("enable %s: %w", ps.name, err)
		}
		// Optional provider: log and carry on with reduced telemetry rather
		// than leaving the user with no sensor at all.
		log.Printf("etw: %s unavailable (%v); continuing without it", ps.name, err)
	}
	if enabled == 0 {
		_ = session.Stop()
		return nil, fmt.Errorf("no ETW providers could be enabled")
	}
	return &etwSource{session: session}, nil
}

// enableWithFallback tries each spec in order, returning nil on the first that
// enables. Windows builds differ in which filter forms they accept.
func enableWithFallback(session *etw.RealTimeSession, ps providerSpec) error {
	var lastErr error
	for i, spec := range ps.specs {
		p, err := etw.ParseProvider(spec)
		if err != nil {
			lastErr = err
			continue
		}
		if err := session.EnableProvider(p); err != nil {
			lastErr = err
			log.Printf("etw: %s spec %q rejected (%v)", ps.name, spec, err)
			continue
		}
		if i > 0 {
			log.Printf("etw: %s enabled via fallback spec %q", ps.name, spec)
		} else {
			log.Printf("etw: %s enabled", ps.name)
		}
		return nil
	}
	return lastErr
}

func (s *etwSource) Events(ctx context.Context) (<-chan event.NormalizedEvent, error) {
	cctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	c := etw.NewRealTimeConsumer(cctx).FromSessions(s.session)
	s.consumer = c

	out := make(chan event.NormalizedEvent)
	c.EventCallback = func(e *etw.Event) error {
		if ne, ok := s.normalize(e); ok {
			select {
			case out <- ne:
			case <-cctx.Done():
			}
		}
		return nil
	}

	if err := c.Start(); err != nil {
		cancel()
		return nil, err
	}
	go func() {
		defer close(out)
		<-cctx.Done()
		_ = c.Stop()
	}()
	return out, nil
}

// normalize maps a parsed ETW event into a NormalizedEvent. It keys off the
// provider channel + opcode; unknown events are dropped (ok=false).
func (s *etwSource) normalize(e *etw.Event) (event.NormalizedEvent, bool) {
	if debugETW {
		dumpRecord(e)
	}

	ne := event.NormalizedEvent{
		Seq:   s.seq.Add(1),
		Time:  e.System.TimeCreated.SystemTime,
		PID:   e.System.Execution.ProcessID,
		Extra: map[string]string{},
	}
	switch e.System.Provider.Name {
	case "Microsoft-Windows-Kernel-Process":
		switch e.System.Opcode.Name {
		case "Start":
			ne.Kind = event.KindProcStart
			ne.PID = u32(e.EventData, ne.PID, "ProcessID", "PID")
			ne.PPID = u32(e.EventData, 0, "ParentProcessID", "ParentPID")
			ne.Image = normalizeImagePath(str(e.EventData, "ImageName", "ImagePath", "ProcessName"))
			// ProcessStartKey is monotonic and never reused, which is what a
			// PID is not. Present from Windows 10 1809; zero on older builds,
			// where attribution falls back to start/exit times alone.
			ne.StartKey = u64(e.EventData, "ProcessStartKey", "ProcessSequenceNumber")
		case "End":
			ne.Kind = event.KindProcExit
			ne.PID = u32(e.EventData, ne.PID, "ProcessID", "PID")
		default:
			return ne, false
		}
	case "Microsoft-Windows-Kernel-Network":
		ne.Kind = event.KindNetConnect
		// The acting process is in the payload ("PID"), NOT the execution
		// context — these events are frequently reported from a system thread
		// (execPID 4), which is why the execution ProcessID names the wrong
		// owner.
		ne.PID = u32(e.EventData, ne.PID, "PID", "ProcessId", "ProcessID")
		// Report both ends verbatim. saddr/daddr are packet-relative: on a
		// receive event daddr is the LOCAL host, so picking daddr blindly
		// records this machine as its own peer. The collector resolves it.
		ne.SrcIP = str(e.EventData, "saddr", "SourceIp", "SourceAddress")
		ne.SrcPort = u16(e.EventData, 0, "sport", "SourcePort")
		ne.RemoteIP = str(e.EventData, "daddr", "DestinationIp", "DestAddr", "RemoteAddress")
		ne.RemotePort = u16(e.EventData, 0, "dport", "DestinationPort", "DestPort", "RemotePort")
		ne.Proto = netProto(e)
		if ne.RemoteIP == "" && ne.SrcIP == "" {
			return ne, false // nothing useful without an address
		}
		// Transfer volume, by direction. The opcode is the only reliable
		// indicator: "Protocol copied data on behalf of user" duplicates the
		// receive event for the same bytes, so counting it would inflate every
		// total roughly twofold.
		if n := u64(e.EventData, "size"); n > 0 {
			switch e.System.Opcode.Name {
			case "Data sent.", "Data sent over UDP protocol.":
				ne.BytesSent = n
			case "Data received.", "Data received over UDP protocol.":
				ne.BytesRecv = n
			}
		}
	case "Microsoft-Windows-DNS-Client", "Microsoft-Windows-DNS-Client-Operational":
		ne.Kind = event.KindDNSQuery
		ne.PID = u32(e.EventData, ne.PID, "PID", "ProcessId", "ProcessID")
		ne.QueryName = str(e.EventData, "QueryName", "DnsQueryName", "Name")
		if ans := str(e.EventData, "QueryResults", "DnsQueryResults", "QueryResult"); ans != "" {
			ne.Answers = parseDNSAnswers(ans)
		}
		if ne.QueryName == "" {
			return ne, false
		}
	case "Microsoft-Windows-Kernel-File":
		// Kernel-File is the volume problem. Create/NameCreate events carry a
		// FileName and a key; Write events carry only the key. Names are
		// therefore learned from create events and looked up on write, and
		// anything we cannot name, or that is not user data, is dropped here
		// rather than carried through the pipeline.
		name := str(e.EventData, "FileName", "FilePath", "OpenPath")
		key := str(e.EventData, "FileKey", "FileObject")

		// A close releases the kernel pointer, so the name must go with it.
		// Nothing did this before, which is half of why a recycled handle
		// inherited the previous file's identity; put() refusing to rebind was
		// the other half.
		switch e.System.Task.Name {
		case "Close", "Cleanup":
			fileNames.forget(key)
			return ne, false
		}

		if name != "" {
			if key != "" && interestingPath(name) {
				fileNames.put(key, name)
			} else if key != "" {
				// Named, but not a path worth alerting on. Drop any cached
				// name for this key rather than leaving the previous one to be
				// found: the handle demonstrably refers to something else now,
				// and "no name" makes the event disappear while a stale name
				// makes it a false accusation against whoever holds the handle.
				fileNames.forget(key)
			}
		} else if key != "" {
			name = fileNames.get(key)
		}
		if name == "" || !interestingPath(name) {
			return ne, false
		}
		kind, ok := fileOperation(e.System.Task.Name)
		if !ok {
			return ne, false
		}
		ne.Kind = kind
		ne.PID = u32(e.EventData, ne.PID, "PID", "ProcessId", "ProcessID")
		ne.Path = normalizeImagePath(name)
	default:
		return ne, false
	}
	return ne, true
}

// fileOperation maps a Kernel-File task to what actually happened.
//
// Treating every file event as a write was a real defect: opening a file picker
// on a folder of photos makes the shell read and thumbnail each one, which
// produced a hundred "modified files" and a ransomware alert for the act of
// choosing a picture to upload. Reads and writes answer different questions —
// reads reveal credential theft, writes reveal encryption — and conflating them
// breaks both.
func fileOperation(task string) (event.Kind, bool) {
	switch task {
	case "Write", "SetInformation", "Rename", "RenamePath", "DeletePath",
		"SetDelete", "Truncate", "SetSecurity", "CreateNewFile":
		// CreateNewFile is a genuinely new file appearing, which is a write in
		// every sense that matters here.
		return event.KindFileWrite, true
	case "Read", "Create", "QueryInformation", "QuerySecurity":
		// Create is an OPEN, not a creation — the shell opens every file it
		// thumbnails. Opening a credential store is exactly the read signal.
		return event.KindFileRead, true
	}
	// NameCreate, OperationEnd, FSCTL, DirEnum and friends are bookkeeping.
	return "", false
}

// fileNames maps ETW file keys to paths. The cache itself lives in
// namecache.go, without a build tag, so its reuse semantics are testable on a
// machine that cannot run ETW — which is every machine this project is
// developed on, and is why the recycled-handle bug survived as long as it did.
//
// Bounded on purpose: a file-name cache that grows with disk activity would be
// a memory leak proportional to I/O, and the machine doing the most I/O is
// exactly the one under attack.
var fileNames = newNameCache(4096)

// skipFragments are the bulk of user-profile I/O and never hold irreplaceable
// data: caches, build output, browser scratch.
var skipFragments = []string{
	`\appdata\local\temp\`,
	`\appdata\local\microsoft\windows\inetcache\`,
	`\appdata\local\packages\`,
	`\node_modules\`,
	`\.git\`,
	`\appdata\locallow\`,
	`\appdata\local\crashdumps\`,
	`\cache\`,
	`\cache2\`,
	`ntuser.dat`,
}

// interestingPath decides whether a file event is worth carrying at all. It
// runs on EVERY file event on the system, so it stays a cheap string test.
func interestingPath(path string) bool {
	p := strings.ToLower(path)
	if !strings.Contains(p, `\users\`) {
		return false // everything we care about lives under a user profile
	}
	for _, skip := range skipFragments {
		if strings.Contains(p, skip) {
			return false
		}
	}
	return true
}

// netProto distinguishes TCP from UDP using the event task/opcode name, which
// carries it on Kernel-Network ("KERNEL_NETWORK_TASK_UDPIP" vs "...TCPIP").
func netProto(e *etw.Event) string {
	name := e.System.Task.Name + " " + e.System.Opcode.Name
	for i := 0; i+2 < len(name); i++ {
		if (name[i] == 'U' || name[i] == 'u') &&
			(name[i+1] == 'D' || name[i+1] == 'd') &&
			(name[i+2] == 'P' || name[i+2] == 'p') {
			return "UDP"
		}
	}
	return "TCP"
}

func (s *etwSource) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.session != nil {
		return s.session.Stop()
	}
	return nil
}

// --- EventData accessors (ETW property maps are stringly-typed) ---

// str returns the first non-empty value among keys. ETW property names differ
// across Windows builds, so every accessor takes candidates rather than one key.
func str(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return t
			}
		case fmt.Stringer:
			if s := t.String(); s != "" {
				return s
			}
		default:
			if s := fmt.Sprintf("%v", v); s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func u32(m map[string]interface{}, def uint32, keys ...string) uint32 {
	if s := str(m, keys...); s != "" {
		if n, err := strconv.ParseUint(s, 0, 32); err == nil {
			return uint32(n)
		}
	}
	return def
}

// u64 reads a numeric payload field.
func u64(m map[string]interface{}, keys ...string) uint64 {
	for _, k := range keys {
		if s := str(m, k); s != "" {
			if n, err := strconv.ParseUint(s, 0, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

func u16(m map[string]interface{}, def uint16, keys ...string) uint16 {
	if s := str(m, keys...); s != "" {
		if n, err := strconv.ParseUint(s, 0, 16); err == nil {
			return uint16(n)
		}
	}
	return def
}
