// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package vt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const goodHash = "1a1bcbb7530fceab56c21490eb55df1f35c87872b125b3577f25f00ad7396cf6"

func body(mal, susp, harm, undet int, names, labels []string) string {
	results := map[string]any{}
	for i, l := range labels {
		results[fmt.Sprintf("Engine%d", i)] = map[string]any{"category": "malicious", "result": l}
	}
	b, _ := json.Marshal(map[string]any{"data": map[string]any{"attributes": map[string]any{
		"last_analysis_stats": map[string]any{
			"malicious": mal, "suspicious": susp, "harmless": harm, "undetected": undet},
		"last_analysis_results": results,
		"names":                 names,
		"reputation":            0,
		"first_submission_date": 1600000000,
		"last_analysis_date":    1700000000,
	}}})
	return string(b)
}

func clientFor(t *testing.T, status int, payload string) (*Client, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Header.Get("x-apikey") == "" {
			t.Error("request sent without an API key")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)
	c := New("test-key")
	c.BaseURL = srv.URL
	return c, &hits
}

// A raw score misleads in both directions. The wording has to carry the
// meaning, because the number alone does not.
func TestVerdictWordingByDetectionCount(t *testing.T) {
	cases := []struct {
		mal, susp     int
		wantIn        string
		adviceMustSay string
	}{
		{45, 0, "45 of", "hostile"},
		{4, 0, "4 of", "seriously"},
		{1, 0, "1 of", "false alarm"},
		{0, 1, "1 of", "false alarm"},
		{0, 0, "None of", "not a guarantee"},
	}
	for _, c := range cases {
		cl, _ := clientFor(t, 200, body(c.mal, c.susp, 30, 40, nil, nil))
		r, err := cl.Lookup(context.Background(), goodHash)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r.Verdict, c.wantIn) {
			t.Errorf("mal=%d susp=%d verdict=%q, want it to contain %q", c.mal, c.susp, r.Verdict, c.wantIn)
		}
		if !strings.Contains(strings.ToLower(r.Advice), c.adviceMustSay) {
			t.Errorf("mal=%d advice=%q, want it to mention %q", c.mal, r.Advice, c.adviceMustSay)
		}
	}
}

// Zero detections must never be presented as proof of safety.
func TestCleanResultIsNotPresentedAsSafe(t *testing.T) {
	cl, _ := clientFor(t, 200, body(0, 0, 30, 42, nil, nil))
	r, _ := cl.Lookup(context.Background(), goodHash)
	low := strings.ToLower(r.Verdict + " " + r.Advice)
	for _, forbidden := range []string{"is safe", "this file is clean and", "guaranteed"} {
		if strings.Contains(low, forbidden) {
			t.Errorf("clean result claims safety: %q", r.Verdict+" "+r.Advice)
		}
	}
	if !strings.Contains(low, "not a guarantee") {
		t.Errorf("a clean result must say what it does not prove: %q", r.Advice)
	}
}

// Never seen is an answer, not a failure — and an interesting one for something
// claiming to be well-known software.
func TestUnknownFileIsAnAnswer(t *testing.T) {
	cl, _ := clientFor(t, 404, `{"error":{"code":"NotFoundError"}}`)
	r, err := cl.Lookup(context.Background(), goodHash)
	if err != nil {
		t.Fatalf("a 404 should not be an error: %v", err)
	}
	if r.Known {
		t.Error("Known should be false")
	}
	if !strings.Contains(strings.ToLower(r.Advice), "not the same as bad") {
		t.Errorf("advice = %q", r.Advice)
	}
}

// The hash goes into a URL path; arriving from our own dashboard is not a
// reason to trust it.
func TestOnlyRealHashesAreSent(t *testing.T) {
	cl, hits := clientFor(t, 200, body(0, 0, 1, 1, nil, nil))
	for _, bad := range []string{"", "not-a-hash", "../../etc/passwd",
		"1a1bcbb7530fceab56c21490eb55df1f35c87872b125b3577f25f00ad7396cf", // 63 chars
		goodHash + "x", "1a1bcbb7530fceab56c21490eb55df1f35c87872b125b3577f25f00ad7396cg"} {
		if _, err := cl.Lookup(context.Background(), bad); err == nil {
			t.Errorf("%q should have been rejected", bad)
		}
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("%d request(s) escaped for invalid input", n)
	}
}

// Repeat presses must not repeat the disclosure.
func TestResultsAreCached(t *testing.T) {
	cl, hits := clientFor(t, 200, body(0, 0, 30, 40, nil, nil))
	for i := 0; i < 5; i++ {
		if _, err := cl.Lookup(context.Background(), goodHash); err != nil {
			t.Fatal(err)
		}
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("VirusTotal was queried %d times for one hash, want 1", n)
	}
}

// Without a key the feature does not exist, rather than failing at the moment
// of use.
func TestDisabledWithoutAKey(t *testing.T) {
	c := New("")
	if c.Enabled() {
		t.Error("should be disabled with no key")
	}
	if _, err := c.Lookup(context.Background(), goodHash); err == nil {
		t.Error("expected an error explaining the key is missing")
	}
}

func TestRateLimitIsExplainedNotJustReported(t *testing.T) {
	cl, _ := clientFor(t, 429, `{}`)
	_, err := cl.Lookup(context.Background(), goodHash)
	if err == nil || !strings.Contains(err.Error(), "four checks a minute") {
		t.Errorf("err = %v, want an explanation of the free allowance", err)
	}
}
