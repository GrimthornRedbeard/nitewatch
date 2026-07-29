// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/legal"
	"github.com/threattape/nitewatch/agent/internal/settings"
)

// tipShow drives the handler and reports whether it wants the notice shown.
func tipShow(t *testing.T, st *settings.Store) bool {
	t.Helper()
	s := New(nil).WithSettings(st)
	rec := httptest.NewRecorder()
	s.handleTip(rec, httptest.NewRequest(http.MethodGet, "/api/tip", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got struct {
		Show bool   `json:"show"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Body == "" {
		t.Error("notice served with no text")
	}
	return got.Show
}

func tipStore(t *testing.T, mutate func(*settings.Values)) *settings.Store {
	t.Helper()
	led, err := ledger.Open(filepath.Join(t.TempDir(), "tip.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { led.Close() })
	st, err := settings.Open(led.SQL(), settings.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	v := st.Get()
	mutate(&v)
	if err := st.Set(v); err != nil {
		t.Fatalf("set: %v", err)
	}
	return st
}

// Being asked for money before being told the software is unfinished, unsigned
// and unwarranted has those two conversations in the wrong order.
func TestTipWaitsForTheDisclaimer(t *testing.T) {
	st := tipStore(t, func(v *settings.Values) { v.AcceptedTerms = "" })
	if tipShow(t, st) {
		t.Error("asked for a contribution before the disclaimer was accepted")
	}
}

func TestTipShowsOnceTermsAccepted(t *testing.T) {
	st := tipStore(t, func(v *settings.Values) { v.AcceptedTerms = legal.Version() })
	if !tipShow(t, st) {
		t.Error("never asks at all")
	}
}

// "Not right now" has to still be true after a reload — the whole point of
// pacing this on the server rather than in the page.
func TestTipStaysAwayAfterSnooze(t *testing.T) {
	st := tipStore(t, func(v *settings.Values) {
		v.AcceptedTerms = legal.Version()
		v.TipSnoozedUnix = time.Now().Unix()
	})
	if tipShow(t, st) {
		t.Error("reappeared immediately after being dismissed")
	}
}

func TestTipReturnsAfterTheInterval(t *testing.T) {
	st := tipStore(t, func(v *settings.Values) {
		v.AcceptedTerms = legal.Version()
		v.TipSnoozedUnix = time.Now().Add(-tipInterval - time.Minute).Unix()
	})
	if !tipShow(t, st) {
		t.Error("dismissal was permanent; it is meant to lapse")
	}
}

// Saying "I contribute" is taken at face value, forever. There is no check and
// there is not going to be one — see internal/tip.
func TestContributorIsNeverAskedAgain(t *testing.T) {
	st := tipStore(t, func(v *settings.Values) {
		v.AcceptedTerms = legal.Version()
		v.Contributor = true
		v.TipSnoozedUnix = time.Now().Add(-365 * 24 * time.Hour).Unix()
	})
	if tipShow(t, st) {
		t.Error("asked a self-declared contributor again")
	}
}

func TestDismissRecordsContributor(t *testing.T) {
	st := tipStore(t, func(v *settings.Values) { v.AcceptedTerms = legal.Version() })
	s := New(nil).WithSettings(st)

	rec := httptest.NewRecorder()
	s.handleDismissTip(rec, httptest.NewRequest(http.MethodPost, "/api/tip/dismiss", nil))
	if v := st.Get(); v.Contributor {
		t.Error("a plain dismissal claimed the user contributes")
	} else if v.TipSnoozedUnix == 0 {
		t.Error("dismissal was not recorded, so it will ask again on reload")
	}

	rec = httptest.NewRecorder()
	s.handleDismissTip(rec, httptest.NewRequest(http.MethodPost, "/api/tip/dismiss?contributor=1", nil))
	if !st.Get().Contributor {
		t.Error("contributor claim was not recorded")
	}
}
