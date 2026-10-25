// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package keystone turns the connection ledger into a file that Keystone, the
// portfolio's correlation tier, can ingest.
//
// One document carries three sections, each in the exact shape one of
// Keystone's connector parsers reads, so a single export feeds all of them:
//
//   - "flows"   → parse_nitewatch_egress  (net.egress: this host talked to X)
//   - "events"  → parse_nitewatch_causal  (nitewatch.causal: which process,
//     spawned by what, caused that egress)
//   - "stories" → the full causal chains, in the versioned Story format
//     (docs/story-format.md), for the explanation contract
//
// The export is a FILE the user asks for. Nothing here opens a socket: the
// product's privacy rule is that nothing leaves the machine on its own, and an
// export is the user carrying their own data somewhere, not the agent sending it.
package keystone

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/threattape/nitewatch/agent/internal/graph"
	"github.com/threattape/nitewatch/agent/internal/ledger"
)

// Schema names the version of the export envelope.
const Schema = "nitewatch.keystone-export/v1"

// Export is the whole document.
type Export struct {
	Schema      string    `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	// Agent identifies the build that recorded the data ("0.1.7-pre (0a0ddbe)"),
	// so a consumer can tell which detector set and attribution logic it holds.
	Agent   string  `json:"agent"`
	SrcHost string  `json:"src_host"`
	Flows   []Flow  `json:"flows"`
	Events  []Event `json:"events"`
	Stories []Story `json:"stories"`
}

// Flow is one egress destination this host contacted (Keystone net.egress).
type Flow struct {
	SrcHost string `json:"src_host"`
	Dst     string `json:"dst"`
	Port    uint16 `json:"port"`
}

// Event is one within-host causal record (Keystone nitewatch.causal): the
// process that made a connection, its parent, and where it went.
//
// ParentPID/ParentImage are present only when the poset actually recorded the
// spawn. They are never guessed from step order — see parentOf.
type Event struct {
	SrcHost     string  `json:"src_host"`
	PID         uint32  `json:"pid"`
	Image       string  `json:"image"`
	UserSID     *string `json:"user_sid"` // not collected by this agent; always null
	ParentPID   *uint32 `json:"parent_pid"`
	ParentImage *string `json:"parent_image"`
	Dst         string  `json:"dst"`
}

// Story is one connection's causal chain.
type Story struct {
	ConnectionID int64           `json:"connection_id"`
	SrcHost      string          `json:"src_host"`
	Dst          string          `json:"dst"`
	Port         uint16          `json:"port"`
	Story        json.RawMessage `json:"story"`
}

// Build assembles an export from ledger rows (newest first, as
// RecentConnections returns them).
//
// Inbound connections are left out: every section describes egress, and a peer
// that connected IN is not somewhere this host went. Flows and events are
// de-duplicated, because the ledger keeps one row per flow and Keystone keys an
// observation on src->dst — a program that reconnects every minute is one fact,
// not a thousand.
func Build(conns []ledger.Connection, host, agent string, now time.Time) Export {
	ex := Export{
		Schema: Schema, GeneratedAt: now.UTC(), Agent: agent, SrcHost: host,
		Flows: []Flow{}, Events: []Event{}, Stories: []Story{},
	}
	seenFlow := map[string]bool{}
	eventAt := map[string]int{}
	for _, c := range conns {
		if c.Inbound || c.RemoteIP == "" {
			continue
		}
		dst := c.Domain
		if dst == "" {
			dst = c.RemoteIP
		}

		fk := dst + "|" + strconv.Itoa(int(c.RemotePort))
		if !seenFlow[fk] {
			seenFlow[fk] = true
			ex.Flows = append(ex.Flows, Flow{SrcHost: host, Dst: dst, Port: c.RemotePort})
		}

		st, ok := decodeStory(c.Story)
		if c.Image != "" {
			ev := Event{SrcHost: host, PID: c.PID, Image: c.Image, Dst: dst}
			if ok {
				if pid, img, found := parentOf(st, c.PID); found {
					ev.ParentPID, ev.ParentImage = &pid, &img
				}
			}
			ek := strconv.Itoa(int(c.PID)) + "|" + c.Image + "|" + dst
			if i, dup := eventAt[ek]; !dup {
				eventAt[ek] = len(ex.Events)
				ex.Events = append(ex.Events, ev)
			} else if ex.Events[i].ParentPID == nil && ev.ParentPID != nil {
				// A later sighting of the same flow recorded the spawn; keep it.
				ex.Events[i] = ev
			}
		}

		if c.Story != "" {
			ex.Stories = append(ex.Stories, Story{
				ConnectionID: c.ID, SrcHost: host, Dst: dst, Port: c.RemotePort,
				Story: json.RawMessage(c.Story),
			})
		}
	}
	// Stable output: the same ledger always exports the same bytes (apart from
	// the timestamp), which keeps a diff between two exports readable.
	sort.SliceStable(ex.Flows, func(i, j int) bool {
		if ex.Flows[i].Dst != ex.Flows[j].Dst {
			return ex.Flows[i].Dst < ex.Flows[j].Dst
		}
		return ex.Flows[i].Port < ex.Flows[j].Port
	})
	return ex
}

func decodeStory(raw string) (graph.Story, bool) {
	if raw == "" {
		return graph.Story{}, false
	}
	var st graph.Story
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return graph.Story{}, false
	}
	return st, true
}

// parentOf finds the process that spawned the connecting process, using the
// story's recorded edges: the ProcStart for pid that has an edge into the
// connection, then the ProcStart with an edge into THAT.
//
// Stories recorded before edges existed (no schema) report no parent. The steps
// are in Lamport order, and the previous ProcStart in that order is very often
// not the parent — a different program's lookup and its whole lineage sit in
// the same chain — so inferring one would hand Keystone exactly the false
// attribution this agent has twice had to fix.
func parentOf(st graph.Story, pid uint32) (uint32, string, bool) {
	if st.Schema == "" || len(st.Edges) == 0 || len(st.Steps) == 0 {
		return 0, "", false
	}
	// The connection is the last step: every other step is its ancestor, so its
	// Lamport clock is strictly the largest.
	anchor := len(st.Steps) - 1
	if st.Steps[anchor].Kind != "NetConnect" {
		return 0, "", false
	}
	preds := map[int][]int{}
	for _, e := range st.Edges {
		if e.From < 0 || e.To < 0 || e.From >= len(st.Steps) || e.To >= len(st.Steps) {
			return 0, "", false // malformed; trust none of it
		}
		preds[e.To] = append(preds[e.To], e.From)
	}
	self := -1
	for _, p := range preds[anchor] {
		if s := st.Steps[p]; s.Kind == "ProcStart" && s.PID == pid {
			self = p
		}
	}
	if self < 0 {
		return 0, "", false
	}
	for _, p := range preds[self] {
		if s := st.Steps[p]; s.Kind == "ProcStart" && s.Image != "" {
			return s.PID, s.Image, true
		}
	}
	return 0, "", false
}
