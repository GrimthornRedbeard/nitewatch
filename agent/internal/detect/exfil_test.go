package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
	"github.com/threattape/nitewatch/agent/internal/rules"
)

// The whole point: answering "what is in that encrypted upload?" without
// decrypting it, by knowing what the program read off disk moments earlier.
func TestUploadAfterReadingSecretsIsExplained(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	now := time.Now()

	e.Exfil().NoteSensitiveRead(77, "your saved Chrome passwords",
		`C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Login Data`, now)

	d := find(e.Evaluate(Subject{
		Event: event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn: ledger.Connection{
			PID: 77, Image: `C:\Users\k\Downloads\stealer.exe`,
			RemoteIP: "203.0.113.9", RemotePort: 443,
			BytesSent: 180 * 1024, LastSeen: now.Add(20 * time.Second),
		},
		Recon:  recon.Info{Org: "SOME-SMALL-HOSTING-LLC", Country: "RU"},
		Domain: "collect.evil.test", HadDNS: true, FirstContact: true,
	}), "c2-exfil-after-secret-read")

	if d == nil {
		t.Fatal("an upload right after reading a password store should fire")
	}
	if d.Rule.Severity != rules.Critical {
		t.Errorf("severity = %s, want critical", d.Rule.Severity)
	}
	narrative := d.Rule.RenderNarrative(d.Fields)
	for _, want := range []string{"Chrome passwords", "180.0 KB", "collect.evil.test"} {
		if !strings.Contains(narrative, want) {
			t.Errorf("narrative missing %q:\n%s", want, narrative)
		}
	}
	// The advice that actually protects someone whose machine is owned.
	if !strings.Contains(strings.ToUpper(strings.Join(d.Rule.RenderPlaybook(d.Fields), " ")), "DIFFERENT") {
		t.Error("playbook must say to change passwords from another device")
	}
}

func TestUploadWithoutASecretReadIsSilent(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	now := time.Now()
	// A big upload on its own is a backup, a video call, a file share.
	if d := find(e.Evaluate(Subject{
		Event: event.NormalizedEvent{Kind: event.KindNetConnect, Signed: true},
		Conn: ledger.Connection{PID: 90, Image: `C:\App\backup.exe`,
			RemoteIP: "203.0.113.9", RemotePort: 443,
			BytesSent: 500 << 20, LastSeen: now},
		Recon: recon.Info{Org: "SOME-HOST"}, Domain: "backup.example", HadDNS: true,
	}), "c2-exfil-after-secret-read"); d != nil {
		t.Fatal("a large upload alone is not evidence of theft")
	}
}

func TestSmallRequestAfterReadIsSilent(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	now := time.Now()
	e.Exfil().NoteSensitiveRead(77, "your saved Chrome passwords", `C:\x\Login Data`, now)
	// Chrome reads its own store constantly and makes small API calls; only a
	// meaningful volume is worth explaining.
	if d := find(e.Evaluate(Subject{
		Event: event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn: ledger.Connection{PID: 77, Image: `C:\App\chrome.exe`,
			RemoteIP: "203.0.113.9", RemotePort: 443,
			BytesSent: 2048, LastSeen: now.Add(time.Second)},
		Recon: recon.Info{Org: "SOME-HOST"}, Domain: "api.example", HadDNS: true,
	}), "c2-exfil-after-secret-read"); d != nil {
		t.Fatal("a small request is not an exfiltration")
	}
}

// A read long ago must not be blamed for unrelated later traffic.
func TestStaleReadDoesNotExplainLaterUpload(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	now := time.Now()
	e.Exfil().NoteSensitiveRead(77, "your saved Chrome passwords", `C:\x\Login Data`, now)
	if d := find(e.Evaluate(Subject{
		Event: event.NormalizedEvent{Kind: event.KindNetConnect},
		Conn: ledger.Connection{PID: 77, Image: `C:\App\app.exe`,
			RemoteIP: "203.0.113.9", RemotePort: 443,
			BytesSent: 1 << 20, LastSeen: now.Add(DefaultExfilWindow + time.Minute)},
		Recon: recon.Info{Org: "SOME-HOST"}, Domain: "api.example", HadDNS: true,
	}), "c2-exfil-after-secret-read"); d != nil {
		t.Fatal("a read outside the window must not explain a later upload")
	}
}
