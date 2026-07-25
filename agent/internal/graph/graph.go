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
	p        *gr.Poset
	procNode map[uint32]gr.EventID // PID -> latest live process node
}

func New() *Graph {
	return &Graph{p: gr.NewPoset(), procNode: make(map[uint32]gr.EventID)}
}

func (g *Graph) Poset() *gr.Poset { return g.p }

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
	case event.KindProcExit:
		delete(g.procNode, e.PID)
	default:
		if proc, ok := g.procNode[e.PID]; ok {
			_ = g.p.AddCausal(proc, ev.ID)
		}
	}
	return ev.ID
}
