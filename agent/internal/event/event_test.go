// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package event

import (
	"encoding/json"
	"testing"
)

func TestNormalizedEventStableKey(t *testing.T) {
	e := NormalizedEvent{Kind: KindNetConnect, PID: 1234, Seq: 7}
	if e.Kind != KindNetConnect {
		t.Fatalf("kind mismatch")
	}
	if got := e.String(); got == "" {
		t.Fatalf("String() should be non-empty")
	}
}

func TestPersistenceEventRoundTripsThroughJSON(t *testing.T) {
	in := NormalizedEvent{
		Seq: 9, Kind: KindRegPersist, PID: 220,
		Image:           `C:\Users\k\Downloads\invoice.exe`,
		PersistKind:     "run-key",
		PersistLocation: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		PersistTarget:   `C:\Users\k\AppData\Roaming\svc.exe`,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out NormalizedEvent
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindRegPersist || out.PersistKind != "run-key" {
		t.Fatalf("persist fields lost: %+v", out)
	}
	if out.PersistLocation != in.PersistLocation || out.PersistTarget != in.PersistTarget {
		t.Fatalf("persist detail lost: %+v", out)
	}
}

func TestSignerFieldsRoundTrip(t *testing.T) {
	in := NormalizedEvent{Seq: 1, Kind: KindProcStart, PID: 4,
		Image: `C:\Windows\System32\svchost.exe`, Signed: true, Signer: "Microsoft Windows"}
	b, _ := json.Marshal(in)
	var out NormalizedEvent
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Signed || out.Signer != "Microsoft Windows" {
		t.Fatalf("signer fields lost: %+v", out)
	}
	// Unsigned is the safe default: absent data must not read as "signed".
	var zero NormalizedEvent
	if zero.Signed {
		t.Fatal("zero value must be unsigned")
	}
}
