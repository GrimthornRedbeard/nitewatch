//go:build windows

package source

import (
	"context"
	"strconv"
	"sync/atomic"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/threattape/nitewatch/agent/internal/event"
)

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
			ne.PID = u32(e.EventData, "ProcessID", ne.PID)
			ne.PPID = u32(e.EventData, "ParentProcessID", 0)
			ne.Image = str(e.EventData, "ImageName")
		case "End":
			ne.Kind = event.KindProcExit
			ne.PID = u32(e.EventData, "ProcessID", ne.PID)
		default:
			return ne, false
		}
	case "Microsoft-Windows-Kernel-Network":
		ne.Kind = event.KindNetConnect
		ne.RemoteIP = firstNonEmpty(str(e.EventData, "daddr"), str(e.EventData, "DestinationIp"))
		ne.RemotePort = u16(e.EventData, "dport", u16(e.EventData, "DestinationPort", 0))
		ne.Proto = "TCP"
	case "Microsoft-Windows-DNS-Client":
		ne.Kind = event.KindDNSQuery
		ne.QueryName = str(e.EventData, "QueryName")
		if ans := str(e.EventData, "QueryResults"); ans != "" {
			ne.Answers = parseDNSAnswers(ans)
		}
	case "Microsoft-Windows-Kernel-File":
		ne.Kind = event.KindFileWrite
		ne.Path = str(e.EventData, "FileName")
	default:
		return ne, false
	}
	return ne, true
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

func str(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func u32(m map[string]interface{}, key string, def uint32) uint32 {
	if s := str(m, key); s != "" {
		if n, err := strconv.ParseUint(s, 0, 32); err == nil {
			return uint32(n)
		}
	}
	return def
}

func u16(m map[string]interface{}, key string, def uint16) uint16 {
	if s := str(m, key); s != "" {
		if n, err := strconv.ParseUint(s, 0, 16); err == nil {
			return uint16(n)
		}
	}
	return def
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseDNSAnswers extracts IP literals from the DNS-Client QueryResults field,
// which is a ';'-separated list mixing "type: value" tokens.
func parseDNSAnswers(raw string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == ';' {
			tok := raw[start:i]
			if c := lastColon(tok); c >= 0 {
				tok = tok[c+1:]
			}
			tok = trimSpace(tok)
			if looksLikeIP(tok) {
				out = append(out, tok)
			}
			start = i + 1
		}
	}
	return out
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}

func looksLikeIP(s string) bool {
	dots, colons := 0, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '.':
			dots++
		case s[i] == ':':
			colons++
		case s[i] >= '0' && s[i] <= '9':
		case (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F'):
		default:
			return false
		}
	}
	return (dots == 3 || colons >= 2) && len(s) > 0
}
