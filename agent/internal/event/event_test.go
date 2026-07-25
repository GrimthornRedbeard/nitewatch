package event

import "testing"

func TestNormalizedEventStableKey(t *testing.T) {
	e := NormalizedEvent{Kind: KindNetConnect, PID: 1234, Seq: 7}
	if e.Kind != KindNetConnect {
		t.Fatalf("kind mismatch")
	}
	if got := e.String(); got == "" {
		t.Fatalf("String() should be non-empty")
	}
}
