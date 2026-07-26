//go:build windows

package source

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
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

func dumpRecord(e *etw.Event) {
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

// etwProviders are the userland ETW providers the flight recorder subscribes to.
// No kernel driver is involved — these are all consumable from an elevated
// userland session.
var etwProviders = []string{
	"Microsoft-Windows-Kernel-Process", // process create/exit
	"Microsoft-Windows-Kernel-Network", // TCP/UDP connects
	"Microsoft-Windows-DNS-Client",     // name resolutions
	"Microsoft-Windows-Kernel-File",    // file create/write/delete/rename
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
	for _, name := range etwProviders {
		p, err := etw.ParseProvider(name)
		if err != nil {
			return nil, err
		}
		if err := session.EnableProvider(p); err != nil {
			return nil, err
		}
	}
	return &etwSource{session: session}, nil
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
			ne.Image = str(e.EventData, "ImageName", "ImagePath", "ProcessName")
		case "End":
			ne.Kind = event.KindProcExit
			ne.PID = u32(e.EventData, ne.PID, "ProcessID", "PID")
		default:
			return ne, false
		}
	case "Microsoft-Windows-Kernel-Network":
		ne.Kind = event.KindNetConnect
		// The acting process is in the payload ("PID"), NOT the execution
		// context — Kernel-Network events are often reported from a system
		// thread, which is why execution ProcessID yields the wrong owner.
		ne.PID = u32(e.EventData, ne.PID, "PID", "ProcessId", "ProcessID")
		ne.RemoteIP = str(e.EventData, "daddr", "DestinationIp", "DestAddr", "RemoteAddress")
		ne.RemotePort = u16(e.EventData, 0, "dport", "DestinationPort", "DestPort", "RemotePort")
		ne.Proto = netProto(e)
		if ne.RemoteIP == "" {
			return ne, false // nothing useful without a destination
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
		ne.Kind = event.KindFileWrite
		ne.PID = u32(e.EventData, ne.PID, "PID", "ProcessId", "ProcessID")
		ne.Path = str(e.EventData, "FileName", "FilePath", "OpenPath")
	default:
		return ne, false
	}
	return ne, true
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

func u16(m map[string]interface{}, def uint16, keys ...string) uint16 {
	if s := str(m, keys...); s != "" {
		if n, err := strconv.ParseUint(s, 0, 16); err == nil {
			return uint16(n)
		}
	}
	return def
}
