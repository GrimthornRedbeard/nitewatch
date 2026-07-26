package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/source"
)

// An agent starting on a running machine has no history: svchost, explorer and
// every service began before it. Without a process-table snapshot, "what
// started this?" has no answer for exactly the processes users ask about most.
func TestSeededProcessTableGivesLineageToPreexistingProcesses(t *testing.T) {
	led, err := ledger.Open(filepath.Join(t.TempDir(), "lineage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer led.Close()

	// A connection from svchost, which the agent never saw start.
	trace := `{"seq":1,"kind":"NetConnect","time":"2026-07-26T12:00:00Z","pid":1200,` +
		`"srcIP":"192.168.1.66","srcPort":50000,"remoteIP":"93.184.216.34","remotePort":443,"proto":"TCP"}`
	path := filepath.Join(t.TempDir(), "svchost.jsonl")
	if err := writeFile(path, trace); err != nil {
		t.Fatal(err)
	}
	src, err := source.NewReplaySource(path)
	if err != nil {
		t.Fatal(err)
	}

	c := NewWithOptions(src, led, Options{
		IncludeLocal: true,
		ProcessTable: func() ([]ProcInfo, error) {
			return []ProcInfo{
				{PID: 4, PPID: 0, Image: `C:\Windows\System32\ntoskrnl.exe`},
				{PID: 800, PPID: 4, Image: `C:\Windows\System32\services.exe`},
				{PID: 1200, PPID: 800, Image: `C:\Windows\System32\svchost.exe`,
					Services: []string{"Windows Update"}},
			}, nil
		},
	})
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	rows, err := led.RecentConnections(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 connection, got %d", len(rows))
	}

	// The service is what a person recognises; the binary name alone is not.
	if !strings.Contains(rows[0].Image, "Windows Update") {
		t.Errorf("connection should be labelled with its service, got %q", rows[0].Image)
	}

	// And the causal chain must now reach back through services.exe.
	var story struct {
		Steps []struct{ Source string } `json:"steps"`
	}
	if err := json.Unmarshal([]byte(rows[0].Story), &story); err != nil {
		t.Fatalf("no causal story recorded: %v", err)
	}
	var chain []string
	for _, s := range story.Steps {
		chain = append(chain, s.Source)
	}
	joined := strings.Join(chain, " -> ")
	if !strings.Contains(joined, "services.exe") {
		t.Errorf("chain should reach back to services.exe, got: %s", joined)
	}
	if !strings.Contains(joined, "svchost.exe") {
		t.Errorf("chain should include svchost.exe, got: %s", joined)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content+"\n"), 0o600)
}
