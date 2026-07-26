package filewatch

import (
	"fmt"
	"testing"
	"time"
)

func TestClassifyUserDocuments(t *testing.T) {
	docs := []string{
		`C:\Users\k\Documents\taxes.xlsx`,
		`C:\Users\k\Desktop\notes.docx`,
		`C:\Users\k\Pictures\wedding.jpg`,
		`C:\Users\k\OneDrive\Documents\report.pdf`,
	}
	for _, p := range docs {
		if got := Classify(p); got != UserDocument {
			t.Errorf("Classify(%s) = %v, want UserDocument", p, got)
		}
	}

	// Build output and caches must never count as irreplaceable data, or the
	// ransomware signal becomes meaningless.
	ignored := []string{
		`C:\Users\k\Documents\project\node_modules\pkg\index.js`,
		`C:\Windows\System32\drivers\etc\hosts`,
		`C:\Users\k\AppData\Local\Temp\build.obj`,
		`C:\Program Files\App\app.dll`,
	}
	for _, p := range ignored {
		if got := Classify(p); got == UserDocument {
			t.Errorf("Classify(%s) counted as a user document", p)
		}
	}
}

func TestClassifyCredentialStores(t *testing.T) {
	cases := map[string]string{
		`C:\Users\k\AppData\Local\Google\Chrome\User Data\Default\Login Data`: "chrome.exe",
		`C:\Users\k\.ssh\id_rsa`:                        "",
		`C:\Users\k\AppData\Roaming\Bitcoin\wallet.dat`: "",
		`C:\Users\k\.aws\credentials`:                   "",
	}
	for path, wantOwner := range cases {
		if got := Classify(path); got != Credential {
			t.Errorf("Classify(%s) = %v, want Credential", path, got)
		}
		what, owner := CredentialInfo(path)
		if what == "" {
			t.Errorf("CredentialInfo(%s) gave no description", path)
		}
		if owner != wantOwner {
			t.Errorf("CredentialInfo(%s) owner = %q, want %q", path, owner, wantOwner)
		}
	}
}

func TestClassifyRansomNotes(t *testing.T) {
	for _, p := range []string{
		`C:\Users\k\Documents\HOW_TO_DECRYPT.txt`,
		`C:\Users\k\Desktop\!!!README.hta`,
		`C:\Users\k\Pictures\_readme.txt`,
	} {
		if got := Classify(p); got != RansomNote {
			t.Errorf("Classify(%s) = %v, want RansomNote", p, got)
		}
	}
}

func TestEncryptedLookingExtension(t *testing.T) {
	// The classic shape: an unfamiliar extension appended to a document.
	for _, p := range []string{
		`C:\Users\k\Documents\taxes.xlsx.locked`,
		`C:\Users\k\Documents\report.docx.encrypted`,
		`C:\Users\k\Pictures\photo.jpg.abcd`,
	} {
		if !EncryptedLookingExt(p) {
			t.Errorf("%s should look encrypted", p)
		}
	}
	// Ordinary files, including ones with unusual-but-known extensions.
	for _, p := range []string{
		`C:\Users\k\Documents\taxes.xlsx`,
		`C:\Users\k\Documents\draft.docx.tmp`,
		`C:\Users\k\Downloads\installer.exe`,
		`C:\Users\k\Documents\notes.txt`,
	} {
		if EncryptedLookingExt(p) {
			t.Errorf("%s must not look encrypted", p)
		}
	}
}

func writeN(tr *Tracker, pid uint32, image string, n int, dirs int, base time.Time, suffix string) Burst {
	var b Burst
	for i := 0; i < n; i++ {
		p := fmt.Sprintf(`C:\Users\k\Documents\dir%d\file%d.docx%s`, i%dirs, i, suffix)
		b = tr.Record(pid, image, p, base.Add(time.Duration(i)*time.Millisecond*100))
	}
	return b
}

// The core distinction: a thousand writes to ONE file is saving; a thousand
// files touched once is encrypting.
func TestRepeatedWritesToOneFileAreNotABurst(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	var b Burst
	for i := 0; i < 500; i++ {
		b = tr.Record(9, "word.exe", `C:\Users\k\Documents\thesis.docx`, now.Add(time.Duration(i)*time.Millisecond))
	}
	if b.Files != 1 {
		t.Fatalf("distinct file count = %d, want 1", b.Files)
	}
	if Assess(b) != Nothing {
		t.Fatal("repeatedly saving one document must not read as ransomware")
	}
}

func TestMassWriteAcrossFoldersIsSuspicious(t *testing.T) {
	tr := NewTracker()
	b := writeN(tr, 9, "evil.exe", MassWriteFiles+5, 5, time.Now(), "")
	if b.Files < MassWriteFiles {
		t.Fatalf("expected the burst to accumulate, got %d files", b.Files)
	}
	if got := Assess(b); got != Suspicious {
		t.Fatalf("Assess = %v, want Suspicious", got)
	}
}

// Volume in a single folder is ordinary bulk work — an unzip, a photo import.
func TestMassWriteInOneFolderIsNotEnough(t *testing.T) {
	tr := NewTracker()
	b := writeN(tr, 9, "unzip.exe", MassWriteFiles+5, 1, time.Now(), "")
	if got := Assess(b); got == Suspicious || got == Confirmed {
		t.Fatalf("bulk work in one folder should not alarm, got %v", got)
	}
}

func TestRenamesConfirmEncryption(t *testing.T) {
	tr := NewTracker()
	b := writeN(tr, 9, "evil.exe", ConfirmedRenames+2, 3, time.Now(), ".locked")
	if b.Renamed < ConfirmedRenames {
		t.Fatalf("renames = %d, want at least %d", b.Renamed, ConfirmedRenames)
	}
	if got := Assess(b); got != Confirmed {
		t.Fatalf("Assess = %v, want Confirmed", got)
	}
}

// A ransom note alongside any file activity removes all doubt.
func TestRansomNoteConfirmsImmediately(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	tr.Record(9, "evil.exe", `C:\Users\k\Documents\a.docx`, now)
	b := tr.Record(9, "evil.exe", `C:\Users\k\Documents\HOW_TO_DECRYPT.txt`, now.Add(time.Second))
	if b.Notes != 1 {
		t.Fatalf("notes = %d, want 1", b.Notes)
	}
	if got := Assess(b); got != Confirmed {
		t.Fatalf("Assess = %v, want Confirmed", got)
	}
}

// Activity must age out, or a slow trickle over hours would eventually look
// like a burst.
func TestWindowExpiresOldActivity(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	writeN(tr, 9, "sync.exe", MassWriteFiles+5, 5, now, "")

	later := tr.Record(9, "sync.exe", `C:\Users\k\Documents\one-more.docx`,
		now.Add(DefaultWindow+time.Minute))
	if later.Files != 1 {
		t.Fatalf("old activity should have expired, got %d files", later.Files)
	}
	if Assess(later) != Nothing {
		t.Fatal("expired activity must not still alarm")
	}
}

func TestSampleGivesTheUserTheirOwnFilenames(t *testing.T) {
	tr := NewTracker()
	b := writeN(tr, 9, "evil.exe", MassWriteFiles+5, 3, time.Now(), "")
	if len(b.Sample) == 0 || len(b.Sample) > 5 {
		t.Fatalf("sample size = %d, want between 1 and 5", len(b.Sample))
	}
}

func TestTrackerBoundsMemory(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	for pid := uint32(1); pid <= 400; pid++ {
		tr.Record(pid, "p.exe", `C:\Users\k\Documents\a.docx`, now.Add(time.Duration(pid)*time.Second))
	}
	tr.mu.Lock()
	n := len(tr.procs)
	tr.mu.Unlock()
	if n > tr.maxTracked {
		t.Fatalf("tracked %d processes, cap is %d", n, tr.maxTracked)
	}
}

func TestShadowCopyToolRecognition(t *testing.T) {
	for _, p := range []string{`C:\Windows\System32\vssadmin.exe`, `C:\Windows\System32\wbadmin.exe`} {
		if !ShadowCopyTool(p) {
			t.Errorf("%s should be recognised as a backup-destruction tool", p)
		}
	}
	if ShadowCopyTool(`C:\Windows\explorer.exe`) {
		t.Error("explorer.exe is not a backup-destruction tool")
	}
}

// Regression, found by an end-to-end replay: ransomware encrypts taxes.xlsx and
// writes taxes.xlsx.locked. Testing only the CURRENT extension made every
// encrypted file invisible, so the detector could fire solely on the ransom
// note — i.e. after the damage was done, and not at all if no note was left.
func TestEncryptedDocumentsStillCountAsUserDocuments(t *testing.T) {
	for _, p := range []string{
		`C:\Users\k\Documents\taxes.xlsx.locked`,
		`C:\Users\k\Pictures\wedding.jpg.encrypted`,
	} {
		if got := Classify(p); got != UserDocument {
			t.Errorf("Classify(%s) = %v, want UserDocument — encrypted documents must still count", p, got)
		}
	}
}

// The same scenario end to end: a sweep with NO ransom note must still be
// caught by the renames alone.
func TestEncryptionSweepWithoutANoteIsStillConfirmed(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	var b Burst
	for i := 0; i < 45; i++ {
		p := fmt.Sprintf(`C:\Users\k\Documents\dir%d\file%d.docx.locked`, i%5, i)
		b = tr.Record(300, "evil.exe", p, now.Add(time.Duration(i)*100*time.Millisecond))
	}
	if b.Files != 45 {
		t.Fatalf("encrypted files must be counted: got %d, want 45", b.Files)
	}
	if b.Dirs != 5 {
		t.Errorf("folders spanned = %d, want 5", b.Dirs)
	}
	if got := Assess(b); got != Confirmed {
		t.Fatalf("a 45-file rename sweep should be Confirmed, got %v", got)
	}
}
