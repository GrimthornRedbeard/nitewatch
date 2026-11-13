// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package seal

import "testing"

func TestSealVerifiesOnlyTheSameFieldsUnderTheSameKey(t *testing.T) {
	k := Ephemeral()
	mac := k.Sum("quarantine-file", `{"path":"a"}`, `{"from":"x","to":"a"}`)
	if !k.Verify(mac, "quarantine-file", `{"path":"a"}`, `{"from":"x","to":"a"}`) {
		t.Fatal("a record does not verify against its own seal")
	}
	if k.Verify(mac, "quarantine-file", `{"path":"a"}`, `{"from":"x","to":"C:\\Windows\\System32\\a"}`) {
		t.Fatal("an edited record verified")
	}
	if Ephemeral().Verify(mac, "quarantine-file", `{"path":"a"}`, `{"from":"x","to":"a"}`) {
		t.Fatal("a seal verified under a different key")
	}
	// Field boundaries are part of what is sealed.
	if k.Verify(k.Sum("ab", "c"), "a", "bc") {
		t.Fatal("moving a field boundary kept the seal valid")
	}
	for _, bad := range []string{"", "zz", "00"} {
		if k.Verify(bad, "quarantine-file") {
			t.Fatalf("mac %q verified", bad)
		}
	}
	var nilKey *Key
	if nilKey.Verify(mac, "quarantine-file") {
		t.Fatal("a nil key verified a record")
	}
}

func TestNewRejectsWrongLength(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("a short key was accepted")
	}
}
