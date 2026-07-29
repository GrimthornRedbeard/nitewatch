// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"

	gr "github.com/ShaneDolphin/gorapide"
)

// Context is what a process was doing, and what led to it running at all.
//
// This is the answer to "why is Brave writing a hundred files?" that a flat log
// cannot give. The lineage says who started it — a program launched by the
// desktop shell is something the user opened; the same program launched by a
// script is not. The recent activity says what else it was doing at the time,
// which is usually what explains the burst.
//
// An honest limit, stated here because the UI must not overclaim: NiteWatch
// sees no keyboard or mouse input, so it cannot know a dialog was clicked. It
// can show that the program was user-launched and what it did — the reader
// draws the conclusion.
type Context struct {
	// Lineage is the ancestry chain, outermost first: explorer.exe -> brave.exe.
	Lineage []string `json:"lineage"`
	// Recent summarises what this process did in the current window, grouped by
	// kind and ordered causally.
	Recent []Activity `json:"recent"`
	// LaunchedBy is the immediate parent, "" when the process predates the agent.
	LaunchedBy string `json:"launchedBy"`
	// UserLaunched reports whether the parent is a shell — the closest we can
	// honestly get to "the person did this".
	UserLaunched bool `json:"userLaunched"`
}

// Activity is one thing a process did, with a count when it did it repeatedly.
type Activity struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	Count  int    `json:"count"`
}

// shells are the processes a person's actions come through. A program started
// by one of these was almost certainly opened by the user; one started by a
// script or service was not.
var shells = map[string]bool{
	"explorer.exe": true, "cmd.exe": true, "powershell.exe": true,
	"pwsh.exe": true, "wt.exe": true, "conhost.exe": true,
	"userinit.exe": true, "taskmgr.exe": true,
}

// ContextFor builds the causal context for the process currently holding a PID.
func (g *Graph) ContextFor(pid uint32) Context { return g.ContextAt(pid, time.Time{}) }

// ContextAt builds the causal context for whichever process held the PID at the
// given instant.
//
// The instant matters. A PID is only unique among live processes, so asking
// "what was this PID doing?" without saying when can blend the histories of
// unrelated programs that happened to share the number.
func (g *Graph) ContextAt(pid uint32, when time.Time) Context {
	var ctx Context

	occ, ok := g.procs.at(pid, when)
	if !ok || occ.node == "" {
		return ctx
	}
	node := occ.node

	// Walk the ancestry through ProcStart events only: the chain of programs
	// that led to this one running.
	var chain []string
	for _, e := range g.p.CausalAncestors(node) {
		if e.Name == string(kindProcStart) {
			chain = append(chain, chainEntry{shortName(e.Source), e.Clock.Lamport}.String())
		}
	}
	sort.Slice(chain, func(i, j int) bool { return chain[i] < chain[j] })
	for _, c := range chain {
		if name := afterBar(c); name != "" {
			ctx.Lineage = append(ctx.Lineage, name)
		}
	}
	if self, ok := g.p.Event(node); ok {
		ctx.Lineage = append(ctx.Lineage, shortName(self.Source))
	}
	if n := len(ctx.Lineage); n >= 2 {
		ctx.LaunchedBy = ctx.Lineage[n-2]
		ctx.UserLaunched = shells[strings.ToLower(ctx.LaunchedBy)]
	}

	ctx.Recent = g.recentActivity(pid, node)
	return ctx
}

// chainEntry sorts ancestry by Lamport clock, which is the causal order —
// wall-clock timestamps tie on a multicore machine.
type chainEntry struct {
	name    string
	lamport uint64
}

func (c chainEntry) String() string { return fmt.Sprintf("%020d|%s", c.lamport, c.name) }

func afterBar(s string) string {
	if i := strings.Index(s, "|"); i >= 0 {
		return s[i+1:]
	}
	return s
}

const kindProcStart = "ProcStart"

// recentActivity summarises what a process did, by walking the events the
// poset attributes to it. Grouped and counted, because "wrote 120 files" is
// useful and 120 individual lines are not.
func (g *Graph) recentActivity(pid uint32, procNode gr.EventID) []Activity {
	type key struct{ kind, detail string }
	counts := map[key]int{}
	order := []key{}

	for _, e := range g.p.CausalDescendants(procNode) {
		if e.Name == kindProcStart {
			continue // covered by lineage
		}
		k := key{kind: e.Name, detail: activityDetail(e)}
		if _, seen := counts[k]; !seen {
			order = append(order, k)
		}
		counts[k]++
	}

	byKind := map[string][]Activity{}
	for _, k := range order {
		byKind[k.kind] = append(byKind[k.kind], Activity{Kind: k.kind, Detail: k.detail, Count: counts[k]})
	}

	// Take the busiest few of EACH kind rather than the busiest overall. A
	// hundred file writes would otherwise crowd out the single DNS lookup and
	// connection that actually explain them — and "it contacted this host, then
	// rewrote your documents" is the sentence worth reading.
	var out []Activity
	for _, kind := range kindOrder {
		group := byKind[kind]
		sort.SliceStable(group, func(i, j int) bool { return group[i].Count > group[j].Count })
		if len(group) > 3 {
			group = group[:3]
		}
		out = append(out, group...)
	}
	// Anything we did not anticipate still gets shown, after the known kinds.
	for kind, group := range byKind {
		if knownKind[kind] {
			continue
		}
		if len(group) > 2 {
			group = group[:2]
		}
		out = append(out, group...)
	}
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

// kindOrder puts the explanatory events first. What a program looked up and
// connected to says WHY; how many files it touched says what happened.
var kindOrder = []string{"DNSQuery", "NetConnect", "RegPersist", "FileWrite", "FileRead"}

var knownKind = func() map[string]bool {
	m := map[string]bool{kindProcStart: true}
	for _, k := range kindOrder {
		m[k] = true
	}
	return m
}()

// activityDetail groups events usefully. File paths collapse to their folder,
// because "wrote 120 files in Pictures" is the fact, not 120 filenames.
func activityDetail(e *gr.Event) string {
	get := func(k string) string {
		if v, ok := e.Params[k]; ok && v != nil {
			s := fmt.Sprintf("%v", v)
			if s != "" && s != "0" && s != "<nil>" {
				return s
			}
		}
		return ""
	}
	switch e.Name {
	case "DNSQuery":
		return get("queryName")
	case "NetConnect":
		if ip, port := get("remoteIP"), get("remotePort"); ip != "" {
			if port != "" {
				return ip + ":" + port
			}
			return ip
		}
	case "FileWrite", "FileRead":
		return folderOf(get("path"))
	}
	return ""
}

func folderOf(p string) string {
	if p == "" {
		return ""
	}
	if i := strings.LastIndexAny(p, `\/`); i > 0 {
		return p[:i]
	}
	return p
}

// Summary renders the context as a sentence for an alert narrative.
func (c Context) Summary() string {
	if len(c.Lineage) == 0 {
		return ""
	}
	var b strings.Builder
	if c.LaunchedBy != "" {
		if c.UserLaunched {
			b.WriteString("Started from " + c.LaunchedBy + ", which usually means you opened it. ")
		} else {
			b.WriteString("Started by " + c.LaunchedBy + ". ")
		}
	}
	if len(c.Lineage) > 1 {
		b.WriteString("Chain: " + strings.Join(c.Lineage, " → ") + ". ")
	}
	return strings.TrimSpace(b.String())
}
