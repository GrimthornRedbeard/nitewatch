// Package graph maintains the live causal event graph: it ingests
// NormalizedEvents into a GoRapide poset and wires causal edges so the agent
// can answer "who caused what" — which process opened a connection, which
// parent spawned a child, which DNS lookup produced the IP a connection used.
package graph

import (
	"time"

	gr "github.com/ShaneDolphin/gorapide"
	"github.com/threattape/nitewatch/agent/internal/event"
)

type Graph struct {
	p *gr.Poset
	// procs maps a PID to the succession of processes that have held it, so an
	// event can be attributed to whichever one was running when it happened
	// rather than to whoever holds the number now. See occupancy.go.
	procs      procTable
	dnsByIP    map[string]dnsRecord  // resolved IP -> most-recent resolution
	connDomain map[gr.EventID]string // connection node -> domain it dialed
}

type dnsRecord struct {
	name string
	node gr.EventID
}

func New() *Graph {
	return &Graph{
		p:          gr.NewPoset(),
		procs:      make(procTable),
		dnsByIP:    make(map[string]dnsRecord),
		connDomain: make(map[gr.EventID]string),
	}
}

func (g *Graph) Poset() *gr.Poset { return g.p }

// ImageFor returns the image path of the process currently holding this PID,
// or "" if unknown. Network and file events carry a PID but no image, so
// attribution comes from the ProcStart the graph already recorded.
//
// Prefer ImageAt when the caller knows when the event happened: this reports
// the CURRENT holder, which is only the right answer for something happening
// now.
func (g *Graph) ImageFor(pid uint32) string {
	if o, ok := g.procs.liveAt(pid); ok {
		return o.image
	}
	if o, ok := g.procs.at(pid, time.Time{}); ok {
		return o.image
	}
	return ""
}

// ImageAt returns the image that held this PID at the given instant.
func (g *Graph) ImageAt(pid uint32, when time.Time) string {
	if o, ok := g.procs.at(pid, when); ok {
		return o.image
	}
	return ""
}

// DomainFor returns the domain a connection node dialed, joined from a prior
// DNS resolution, or "" if the connection went to a raw IP with no lookup.
func (g *Graph) DomainFor(id gr.EventID) string { return g.connDomain[id] }

// KnownNameFor reports the domain most recently resolved to an address by ANY
// process, independent of poset nodes. Used to carry resolutions across a
// window rotation.
func (g *Graph) KnownNameFor(ip string) string { return g.dnsByIP[ip].name }

// DNSAnswers exports the address-to-name map so a fresh window generation can
// inherit it. Without this, every rotation blinds the DNS join and connections
// that DID follow a lookup are reported as bare-address contacts.
func (g *Graph) DNSAnswers() map[string]string {
	out := make(map[string]string, len(g.dnsByIP))
	for ip, rec := range g.dnsByIP {
		out[ip] = rec.name
	}
	return out
}

// SeedDNSAnswers restores name resolutions into a new generation. The causal
// edge back to the original DNSQuery node is necessarily lost — that event is
// gone — but the NAME survives, which is what the ledger and the "did this
// program look it up?" test both depend on.
func (g *Graph) SeedDNSAnswers(answers map[string]string) {
	for ip, name := range answers {
		if _, exists := g.dnsByIP[ip]; !exists {
			g.dnsByIP[ip] = dnsRecord{name: name}
		}
	}
}

// Ingest adds one normalized event to the poset, wiring causal edges, and
// returns the new node's EventID.
func (g *Graph) Ingest(e event.NormalizedEvent) gr.EventID {
	ev := gr.NewEvent(string(e.Kind), e.Image, map[string]any{
		"pid":        e.PID,
		"remoteIP":   e.RemoteIP,
		"remotePort": e.RemotePort,
		"queryName":  e.QueryName,
		"path":       e.Path,
		"seq":        e.Seq,
	})
	_ = g.p.AddEvent(ev)

	// An event that carries its own image is direct evidence of who held the PID
	// at that moment. If it disagrees with the tenure we would otherwise use,
	// the PID changed hands without us seeing it — close the old tenure and
	// open one for the newcomer, rather than chaining this event onto a
	// stranger's history.
	if e.Kind != event.KindProcStart && e.Image != "" {
		if known, ok := g.procs.at(e.PID, e.Time); ok && known.image != "" &&
			!sameImage(known.image, e.Image) {
			g.procs.end(e.PID, e.Time)
			g.procs.begin(e.PID, occupant{image: e.Image, start: e.Time})
		}
	}

	switch e.Kind {
	case event.KindProcStart:
		// Parent linking resolves at the CHILD's start time: the parent must
		// have been alive to spawn it, and a PPID that has since been recycled
		// would otherwise attach this process to an unrelated one.
		if e.PPID != 0 {
			if parent, ok := g.procs.at(e.PPID, e.Time); ok && parent.node != "" {
				_ = g.p.AddCausal(parent.node, ev.ID)
			}
		}
		g.procs.begin(e.PID, occupant{
			key: e.StartKey, image: e.Image, node: ev.ID, start: e.Time,
		})
	case event.KindProcExit:
		g.procs.end(e.PID, e.Time)
	case event.KindDNSQuery:
		if proc, ok := g.procs.at(e.PID, e.Time); ok && proc.node != "" {
			_ = g.p.AddCausal(proc.node, ev.ID)
		}
		for _, ip := range e.Answers {
			g.dnsByIP[ip] = dnsRecord{name: e.QueryName, node: ev.ID}
		}
	case event.KindNetConnect:
		if proc, ok := g.procs.at(e.PID, e.Time); ok && proc.node != "" {
			_ = g.p.AddCausal(proc.node, ev.ID)
		}
		if rec, ok := g.dnsByIP[e.RemoteIP]; ok {
			g.connDomain[ev.ID] = rec.name
			// A seeded resolution carried across a rotation has no surviving
			// node to link to; the name is still valid.
			if rec.node != "" {
				_ = g.p.AddCausal(rec.node, ev.ID)
			}
		}
	default:
		if proc, ok := g.procs.at(e.PID, e.Time); ok && proc.node != "" {
			_ = g.p.AddCausal(proc.node, ev.ID)
		}
	}
	return ev.ID
}
