package detect

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/filewatch"
	"github.com/threattape/nitewatch/agent/internal/rules"
)

func loadFilePacks(t *testing.T) *rules.Set {
	t.Helper()
	var packs []*rules.Pack
	for _, f := range []string{"../../rules/ransomware.yaml", "../../rules/credentials.yaml"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		p, err := rules.LoadPack(data)
		if err != nil {
			t.Fatalf("shipped pack %s does not load: %v", f, err)
		}
		packs = append(packs, p)
	}
	return rules.NewSet(packs...)
}

func burstOf(t *testing.T, files, dirs int, suffix string) filewatch.Burst {
	t.Helper()
	tr := filewatch.NewTracker()
	now := time.Now()
	var b filewatch.Burst
	for i := 0; i < files; i++ {
		p := `C:\Users\k\Documents\d` + string(rune('0'+i%dirs)) + `\f` +
			string(rune('a'+i%26)) + string(rune('a'+i/26)) + `.docx` + suffix
		b = tr.Record(9, `C:\Users\k\Downloads\evil.exe`, p, now.Add(time.Duration(i)*100*time.Millisecond))
	}
	return b
}

func TestConfirmedRansomwareIsCriticalAndActionable(t *testing.T) {
	e := New(loadFilePacks(t), nil)
	s := FileSubject{PID: 9, Image: `C:\Users\k\Downloads\evil.exe`,
		Burst: burstOf(t, filewatch.ConfirmedRenames+5, 3, ".locked")}

	d := find(e.EvaluateFile(s), "ransomware-confirmed")
	if d == nil {
		t.Fatal("confirmed encryption should fire")
	}
	if d.Rule.Severity != rules.Critical {
		t.Errorf("severity = %s, want critical", d.Rule.Severity)
	}
	// The first step must be the one that limits damage — minutes matter here.
	steps := d.Rule.RenderPlaybook(d.Fields)
	if len(steps) == 0 || !strings.Contains(strings.ToLower(steps[0]), "stop") {
		t.Errorf("the first instruction must be to stop it: %+v", steps)
	}
	narrative := d.Rule.RenderNarrative(d.Fields)
	if !strings.Contains(narrative, "renamed") {
		t.Errorf("narrative should say what the evidence was:\n%s", narrative)
	}
}

// Backup and sync tools legitimately rewrite thousands of files. Alerting on
// every backup would train users to ignore the confirmed case too.
func TestTrustedBackupSoftwareDoesNotTripSuspectedRule(t *testing.T) {
	e := New(loadFilePacks(t), nil)
	s := FileSubject{
		PID: 9, Image: `C:\Program Files\Google\Drive\googledrivesync.exe`,
		Signed: true, Signer: "Google LLC",
		Burst: burstOf(t, filewatch.MassWriteFiles+10, 5, ""),
	}
	if d := find(e.EvaluateFile(s), "ransomware-suspected"); d != nil {
		t.Fatal("a signed, trusted sync client must not be reported as ransomware")
	}

	// The same volume from an unsigned program in Downloads is worth a warning.
	s.Signed, s.Signer = false, ""
	s.Image = `C:\Users\k\Downloads\thing.exe`
	if d := find(e.EvaluateFile(s), "ransomware-suspected"); d == nil {
		t.Fatal("the same volume from unsigned software should warn")
	}
}

// Even a trusted publisher does not get to encrypt files and leave a note.
func TestConfirmedFiresRegardlessOfPublisher(t *testing.T) {
	e := New(loadFilePacks(t), nil)
	s := FileSubject{
		PID: 9, Image: `C:\Program Files\Trusted\app.exe`, Signed: true, Signer: "Microsoft Windows",
		Burst: burstOf(t, filewatch.ConfirmedRenames+5, 3, ".locked"),
	}
	if d := find(e.EvaluateFile(s), "ransomware-confirmed"); d == nil {
		t.Fatal("confirmed encryption must fire regardless of who signed the program")
	}
}

func TestBackupDestructionFires(t *testing.T) {
	e := New(loadFilePacks(t), nil)
	s := FileSubject{PID: 9, Image: `C:\Windows\System32\vssadmin.exe`, ToolRun: "vssadmin.exe"}
	d := find(e.EvaluateFile(s), "ransomware-backup-destruction")
	if d == nil {
		t.Fatal("backup destruction should fire")
	}
	if d.Rule.Severity != rules.Critical {
		t.Errorf("severity = %s, want critical", d.Rule.Severity)
	}
}

// The whole credential rule: Chrome reading Chrome's password store is Chrome
// working. Anything else reading it is an information stealer.
func TestCredentialTheftComparesReaderAgainstOwner(t *testing.T) {
	e := New(loadFilePacks(t), nil)
	const loginData = `C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Login Data`

	owner := FileSubject{PID: 1, Image: `C:\Program Files\Google\Chrome\Application\chrome.exe`, Path: loginData}
	if d := find(e.EvaluateFile(owner), "credential-theft"); d != nil {
		t.Fatal("Chrome reading its own password store must be silent")
	}

	stranger := FileSubject{PID: 2, Image: `C:\Users\k\Downloads\invoice.exe`, Path: loginData}
	d := find(e.EvaluateFile(stranger), "credential-theft")
	if d == nil {
		t.Fatal("an unrelated program reading saved passwords must fire")
	}
	if d.Rule.Severity != rules.Critical {
		t.Errorf("severity = %s, want critical", d.Rule.Severity)
	}
	narrative := d.Rule.RenderNarrative(d.Fields)
	if !strings.Contains(narrative, "Chrome") || !strings.Contains(narrative, "chrome.exe") {
		t.Errorf("narrative should name the secret and its owner:\n%s", narrative)
	}
	// The advice that actually protects the user: change passwords elsewhere.
	steps := strings.Join(d.Rule.RenderPlaybook(d.Fields), " ")
	if !strings.Contains(strings.ToUpper(steps), "DIFFERENT") {
		t.Error("the playbook must tell the user to change passwords from another device")
	}
}

func TestWindowsComponentsDoNotTripCredentialRule(t *testing.T) {
	e := New(loadFilePacks(t), nil)
	s := FileSubject{PID: 4, Image: `C:\Windows\System32\svchost.exe`,
		Path: `C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Login Data`}
	if d := find(e.EvaluateFile(s), "credential-theft"); d != nil {
		t.Fatal("Windows components must not trip the credential rule")
	}
}

func TestOrdinaryFileActivityIsSilent(t *testing.T) {
	e := New(loadFilePacks(t), nil)
	tr := filewatch.NewTracker()
	now := time.Now()
	var b filewatch.Burst
	for i := 0; i < 5; i++ {
		b = tr.Record(9, "word.exe", `C:\Users\k\Documents\thesis.docx`, now.Add(time.Duration(i)*time.Second))
	}
	s := FileSubject{PID: 9, Image: `C:\Program Files\Office\word.exe`, Signed: true, Signer: "Microsoft", Burst: b}
	if got := e.EvaluateFile(s); len(got) != 0 {
		for _, d := range got {
			t.Errorf("ordinary editing fired %s", d.Rule.ID)
		}
	}
}
