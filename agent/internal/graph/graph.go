// Package graph maintains the live causal event graph: it ingests
// NormalizedEvents into a GoRapide poset and wires causal edges so the agent
// can answer "who caused what" — which process opened a connection, which
// parent spawned a child, which DNS lookup produced the IP a connection used.
package graph

import (
	gr "github.com/ShaneDolphin/gorapide"
	"github.com/threattape/nitewatch/agent/internal/event"
)

type Graph struct {
	p          *gr.Poset
	procNode   map[uint32]gr.EventID // PID -> latest live process node
	procImage  map[uint32]string     // PID -> image path of the live process
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
		procNode:   make(map[uint32]gr.EventID),
		procImage:  make(map[uint32]string),
		dnsByIP:    make(map[string]dnsRecord),
		connDomain: make(map[gr.EventID]string),
	}
}

func (g *Graph) Poset() *gr.Poset { return g.p }

// ImageFor returns the image path of the live process with this PID, or "" if
// unknown. Network/file events carry a PID but no image, so attribution comes
// from the ProcStart the graph already recorded.
func (g *Graph) ImageFor(pid uint32) string { return g.procImage[pid] }

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

	switch e.Kind {
	case event.KindProcStart:
		if e.PPID != 0 {
			if parent, ok := g.procNode[e.PPID]; ok {
				_ = g.p.AddCausal(parent, ev.ID)
			}
		}
		g.procNode[e.PID] = ev.ID
		if e.Image != "" {
			g.procImage[e.PID] = e.Image
		}
	case event.KindProcExit:
		delete(g.procNode, e.PID)
		delete(g.procImage, e.PID)
	case event.KindDNSQuery:
		if proc, ok := g.procNode[e.PID]; ok {
			_ = g.p.AddCausal(proc, ev.ID)
		}
		for _, ip := range e.Answers {
			g.dnsByIP[ip] = dnsRecord{name: e.QueryName, node: ev.ID}
		}
	case event.KindNetConnect:
		if proc, ok := g.procNode[e.PID]; ok {
			_ = g.p.AddCausal(proc, ev.ID)
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
		if proc, ok := g.procNode[e.PID]; ok {
			_ = g.p.AddCausal(proc, ev.ID)
		}
	}
	return ev.ID
}
