package graph

import (
	"fmt"
	"sort"
	"strings"

	gr "github.com/ShaneDolphin/gorapide"
)

// Story is the causal explanation of a single connection: the chain of events
// that led to it, extracted from the poset.
//
// This is what the GoRapide dependency is FOR. Everything else the agent does
// with events could be a flat log; the poset is what lets us answer "what
// caused this connection?" — the browser that spawned the helper that resolved
// the name that produced the address this program dialed.
type Story struct {
	Steps   []Step `json:"steps"`
	Mermaid string `json:"mermaid"`
	// Narrative is the chain written as prose. Stored rather than regenerated
	// so the account of an event never changes after the fact.
	Narrative string `json:"narrative,omitempty"`
	// Context is what else the program was doing, kept with the story so the
	// full picture survives the causal window rolling over.
	Context *Context `json:"context,omitempty"`
}

// Step is one event in the causal chain, in happens-before order.
type Step struct {
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	Detail  string `json:"detail"`
	Lamport uint64 `json:"lamport"`
}

// StoryFor walks the causal ancestors of an event and renders them as an
// ordered narrative plus a Mermaid diagram.
//
// GoRapide does the real work here: CausalAncestors traverses the DAG we built
// while ingesting, and the Lamport clock supplies a happens-before ordering
// that wall-clock timestamps cannot (concurrent events on a multicore box can
// share a timestamp, and ETW delivery order is not causal order).
func (g *Graph) StoryFor(id gr.EventID) Story {
	anchor, ok := g.p.Event(id)
	if !ok {
		return Story{}
	}

	// Ancestors ∪ the anchor itself = the full chain that produced this event.
	nodes := []*gr.Event{anchor}
	for _, e := range g.p.CausalAncestors(id) {
		nodes = append(nodes, e)
	}

	// Lamport order is the causal order; ties break by name for stability.
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Clock.Lamport != nodes[j].Clock.Lamport {
			return nodes[i].Clock.Lamport < nodes[j].Clock.Lamport
		}
		return nodes[i].Name < nodes[j].Name
	})

	st := Story{Steps: make([]Step, 0, len(nodes))}
	for _, e := range nodes {
		st.Steps = append(st.Steps, Step{
			Kind:    e.Name,
			Source:  shortName(e.Source),
			Detail:  detailOf(e),
			Lamport: e.Clock.Lamport,
		})
	}
	st.Mermaid = mermaidChain(nodes)
	return st
}

// detailOf renders the interesting parameter of an event for display.
func detailOf(e *gr.Event) string {
	get := func(k string) string {
		if v, ok := e.Params[k]; ok && v != nil {
			s := fmt.Sprintf("%v", v)
			if s != "" && s != "0" {
				return s
			}
		}
		return ""
	}
	switch e.Name {
	case "ProcStart", "ProcExit":
		if pid := get("pid"); pid != "" {
			return "pid " + pid
		}
	case "DNSQuery":
		return get("queryName")
	case "NetConnect":
		ip, port := get("remoteIP"), get("remotePort")
		if ip != "" && port != "" {
			return ip + ":" + port
		}
		return ip
	case "FileWrite":
		return get("path")
	}
	return ""
}

// mermaidChain renders the causal chain as a Mermaid flowchart. GoRapide ships
// a whole-poset Mermaid exporter; we render just this subgraph so the UI shows
// one story rather than the entire machine's activity.
func mermaidChain(nodes []*gr.Event) string {
	if len(nodes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("flowchart TD\n")
	for i, e := range nodes {
		label := e.Name
		if src := shortName(e.Source); src != "" {
			label = src + "<br/>" + label
		}
		if d := detailOf(e); d != "" {
			label += "<br/>" + d
		}
		fmt.Fprintf(&b, "  n%d[\"%s\"]\n", i, escapeMermaid(label))
	}
	for i := 1; i < len(nodes); i++ {
		fmt.Fprintf(&b, "  n%d --> n%d\n", i-1, i)
	}
	return b.String()
}

// shortName reduces a full image path to its executable name.
func shortName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func escapeMermaid(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
