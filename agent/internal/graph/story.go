// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

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
	// Schema names the version of this shape. Stories recorded before it existed
	// have no schema and no edges; readers must treat both as optional. See
	// docs/story-format.md, which is the contract other products read.
	Schema string `json:"schema,omitempty"`
	Steps  []Step `json:"steps"`
	// Edges are the poset's direct causal edges between Steps, as indices into
	// Steps. They are the real graph: Steps alone is a Lamport-ordered list, and
	// two adjacent steps are not necessarily cause and effect — the lookup that
	// produced an address may have been made by a different program than the one
	// that dialed it.
	Edges   []Edge `json:"edges,omitempty"`
	Mermaid string `json:"mermaid"`
	// Narrative is the chain written as prose. Stored rather than regenerated
	// so the account of an event never changes after the fact.
	Narrative string `json:"narrative,omitempty"`
	// Context is what else the program was doing, kept with the story so the
	// full picture survives the causal window rolling over.
	Context *Context `json:"context,omitempty"`
}

// StorySchema is the version stamped on every Story recorded from now on.
const StorySchema = "nitewatch.story/v1"

// Step is one event in the causal chain, in happens-before order.
type Step struct {
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	Detail  string `json:"detail"`
	Lamport uint64 `json:"lamport"`
	// PID and Image identify the process the event belongs to. Source is the
	// display form of Image; Image is the full path a consumer can match on.
	PID   uint32 `json:"pid,omitempty"`
	Image string `json:"image,omitempty"`
}

// Edge is one direct causal edge: Steps[From] caused Steps[To].
type Edge struct {
	From int `json:"from"`
	To   int `json:"to"`
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

	index := make(map[gr.EventID]int, len(nodes))
	for i, e := range nodes {
		index[e.ID] = i
	}

	st := Story{Schema: StorySchema, Steps: make([]Step, 0, len(nodes))}
	for _, e := range nodes {
		st.Steps = append(st.Steps, Step{
			Kind:    e.Name,
			Source:  shortName(e.Source),
			Detail:  detailOf(e),
			Lamport: e.Clock.Lamport,
			PID:     pidOf(e),
			Image:   e.Source,
		})
	}
	// The chain is the anchor plus ALL its ancestors, so every direct
	// predecessor of a chain node is itself in the chain; the lookup never
	// misses. Sorted so the same poset always serializes to the same bytes.
	for to, e := range nodes {
		for _, pred := range g.p.DirectPredecessors(e.ID) {
			if from, ok := index[pred]; ok {
				st.Edges = append(st.Edges, Edge{From: from, To: to})
			}
		}
	}
	sort.Slice(st.Edges, func(i, j int) bool {
		if st.Edges[i].To != st.Edges[j].To {
			return st.Edges[i].To < st.Edges[j].To
		}
		return st.Edges[i].From < st.Edges[j].From
	})
	st.Mermaid = mermaidChain(nodes, st.Edges)
	return st
}

// pidOf reads the PID parameter Ingest stored on every event.
func pidOf(e *gr.Event) uint32 {
	if v, ok := e.Params["pid"].(uint32); ok {
		return v
	}
	return 0
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
//
// Arrows are the poset's edges. An earlier version joined the steps in Lamport
// order instead, which drew a chain of cause and effect between events that
// were merely ordered — the same misattribution the Edges field exists to stop.
func mermaidChain(nodes []*gr.Event, edges []Edge) string {
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
	for _, e := range edges {
		fmt.Fprintf(&b, "  n%d --> n%d\n", e.From, e.To)
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
