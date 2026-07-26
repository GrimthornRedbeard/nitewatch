package detect

import (
	"os"
	"strings"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/autostart"
	"github.com/threattape/nitewatch/agent/internal/rules"
)

// Exercises the SHIPPED persistence pack, so a broken rule fails the build.
func loadPersistPack(t *testing.T) *rules.Set {
	t.Helper()
	data, err := os.ReadFile("../../rules/persistence.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := rules.LoadPack(data)
	if err != nil {
		t.Fatalf("shipped persistence pack does not load: %v", err)
	}
	return rules.NewSet(p)
}

func persistOf(kind autostart.Kind, name, target, previous string) PersistSubject {
	return PersistSubject{Change: autostart.Change{
		Entry:    autostart.Entry{Kind: kind, Location: `HKCU\...\Run`, Name: name, Target: target},
		Previous: previous,
	}}
}

func TestImageHijackIsCritical(t *testing.T) {
	e := New(loadPersistPack(t), nil)
	s := persistOf(autostart.KindIFEO, "notepad.exe", `C:\Users\k\AppData\evil.exe`, "")
	d := find(e.EvaluatePersistence(s), "persist-image-hijack")
	if d == nil {
		t.Fatal("an image-hijack registration should fire")
	}
	if d.Rule.Severity != rules.Critical {
		t.Errorf("severity = %s, want critical", d.Rule.Severity)
	}
	title := d.Rule.RenderTitle(d.Fields)
	if !strings.Contains(title, "notepad.exe") {
		t.Errorf("title should name the hijacked program: %q", title)
	}
}

// The hijack case that matters most: something inherits the trust already
// placed in an existing startup entry by swapping what it runs.
func TestTargetReplacementFiresWithBothTargets(t *testing.T) {
	e := New(loadPersistPack(t), nil)
	s := persistOf(autostart.KindRunKey, "OneDrive",
		`C:\Users\k\AppData\Roaming\evil.exe`, `C:\Program Files\OneDrive\OneDrive.exe`)

	d := find(e.EvaluatePersistence(s), "persist-autostart-replaced")
	if d == nil {
		t.Fatal("a replaced autostart target should fire")
	}
	narrative := d.Rule.RenderNarrative(d.Fields)
	if !strings.Contains(narrative, "OneDrive.exe") || !strings.Contains(narrative, "evil.exe") {
		t.Errorf("narrative must show what it used to run and what it runs now:\n%s", narrative)
	}
}

func TestAutostartFromTempLocationFires(t *testing.T) {
	e := New(loadPersistPack(t), nil)
	for _, target := range []string{
		`C:\Users\k\Downloads\invoice.exe`,
		`C:\Users\k\AppData\Local\Temp\svc.exe`,
		`C:\Windows\Temp\x.exe`,
	} {
		s := persistOf(autostart.KindRunKey, "Updater", target, "")
		if d := find(e.EvaluatePersistence(s), "persist-from-temp-location"); d == nil {
			t.Errorf("autostart from %s should fire", target)
		}
	}

	// Installed software in Program Files is the normal case.
	normal := persistOf(autostart.KindRunKey, "App", `C:\Program Files\App\app.exe`, "")
	if d := find(e.EvaluatePersistence(normal), "persist-from-temp-location"); d != nil {
		t.Error("Program Files is where installed software belongs; must not fire")
	}
}

// Several mainstream apps legitimately install per-user into AppData. A
// verified signature from a known publisher must not be treated as a bad drop.
func TestSignedTrustedPublisherInAppDataIsQuiet(t *testing.T) {
	e := New(loadPersistPack(t), nil)
	s := persistOf(autostart.KindRunKey, "Discord", `C:\Users\k\AppData\Local\Discord\Update.exe`, "")
	s.Signed = true
	s.Signer = "Discord Inc."

	if d := find(e.EvaluatePersistence(s), "persist-from-temp-location"); d != nil {
		t.Error("a signed, trusted publisher installing per-user must not fire the temp-location rule")
	}
	if d := find(e.EvaluatePersistence(s), "persist-unsigned-autostart"); d != nil {
		t.Error("a signed program must not fire the unsigned rule")
	}
}

func TestUnsignedAutostartFiresButWindowsComponentsDoNot(t *testing.T) {
	e := New(loadPersistPack(t), nil)

	unsigned := persistOf(autostart.KindRunKey, "Thing", `C:\Tools\thing.exe`, "")
	if d := find(e.EvaluatePersistence(unsigned), "persist-unsigned-autostart"); d == nil {
		t.Error("an unsigned autostart should fire")
	}

	// Windows' own components are not meaningfully "unsigned" even when we
	// could not read a signature.
	sysComponent := persistOf(autostart.KindRunKey, "SecurityHealth", `C:\Windows\System32\SecurityHealthSystray.exe`, "")
	if d := find(e.EvaluatePersistence(sysComponent), "persist-unsigned-autostart"); d != nil {
		t.Error("Windows system components must not fire the unsigned rule")
	}
}

// Ordinary software installing itself normally must be completely silent.
func TestNormalInstallIsSilent(t *testing.T) {
	e := New(loadPersistPack(t), nil)
	s := persistOf(autostart.KindRunKey, "SomeApp", `"C:\Program Files\SomeApp\app.exe" --background`, "")
	s.Signed = true
	s.Signer = "SomeApp Ltd"

	if got := e.EvaluatePersistence(s); len(got) != 0 {
		for _, d := range got {
			t.Errorf("normal signed install in Program Files fired %s", d.Rule.ID)
		}
	}
}

// Winlogon holds legitimate defaults; only a CHANGE to them is interesting.
func TestWinlogonDefaultsAreNotThemselvesAlerts(t *testing.T) {
	e := New(loadPersistPack(t), nil)
	baseline := persistOf(autostart.KindWinlogon, "Shell", "explorer.exe", "")
	if d := find(e.EvaluatePersistence(baseline), "persist-image-hijack"); d != nil {
		t.Error("observing the Winlogon default for the first time must not alert")
	}

	changed := persistOf(autostart.KindWinlogon, "Shell", `explorer.exe,C:\Users\k\AppData\evil.exe`, "explorer.exe")
	if d := find(e.EvaluatePersistence(changed), "persist-image-hijack"); d == nil {
		t.Error("a CHANGED Winlogon shell should fire")
	}
}
