package detect

import (
	"testing"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
)

// Verbatim from a live desktop: WhatsApp from the Microsoft Store, reported as
// "software with no publisher" because Get-AuthenticodeSignature finds no
// embedded signature on the .exe inside an MSIX package. Every Store app the
// user owned tripped this.
func TestStoreAppsAreVouchedDespiteNoEmbeddedSignature(t *testing.T) {
	store := []string{
		`C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2627.101.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe`,
		`C:\Program Files\WindowsApps\Claude_1.24012.9.0_x64__pzs8sxrjxfjjc\app\claude.exe`,
		`C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe`,
	}
	for _, p := range store {
		it := ClassifyInstall(p, false, "")
		if !it.Vouched || !it.Store {
			t.Errorf("%s: should be vouched as a Store app, got %+v", p, it)
		}
		if it.Why == "" {
			t.Errorf("%s: no explanation given", p)
		}
	}
}

// System32 is writable by administrators and dropping a binary there is a
// standard malware move, so location must prove nothing about it. Windows' own
// files carry catalog signatures the check reads correctly, so they need no
// exemption.
func TestSystem32IsNotTrustedByLocation(t *testing.T) {
	if PublisherVouched(`C:\Windows\System32\evil.exe`, false, "") {
		t.Error("an UNSIGNED binary in System32 must not be trusted by location")
	}
	if !PublisherVouched(`C:\Windows\System32\svchost.exe`, true, "Microsoft Windows") {
		t.Error("a signed System32 binary is vouched by its signature")
	}
}

func TestOrdinaryUnsignedProgramsAreNotVouched(t *testing.T) {
	for _, p := range []string{
		`C:\Users\k\AppData\Local\Temp\sync-helper.exe`,
		`C:\Users\k\Downloads\invoice.exe`,
		`C:\Program Files\SomeApp\app.exe`,
		``,
	} {
		if PublisherVouched(p, false, "") {
			t.Errorf("%s: must not be vouched", p)
		}
	}
}

// The publisher hash in the folder name is what somebody checking a program
// actually wants: it is derived from the signing certificate and cannot be
// forged without it.
func TestStorePackageIdentity(t *testing.T) {
	name, ver, pub, ok := StorePackage(
		`C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2627.101.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe`)
	if !ok {
		t.Fatal("should parse a WindowsApps path")
	}
	if name != "5319275A.WhatsAppDesktop" {
		t.Errorf("name = %q", name)
	}
	if ver != "2.2627.101.0" {
		t.Errorf("version = %q", ver)
	}
	if pub != "cv1g1gvanyjgm" {
		t.Errorf("publisherID = %q", pub)
	}
	if _, _, _, ok := StorePackage(`C:\Users\k\Downloads\x.exe`); ok {
		t.Error("a non-Store path should not parse")
	}
}

// Verbatim from the report: WhatsApp from the Microsoft Store, contacting
// whatsapp.net, reported as "has no publisher signature and just contacted a
// new server". The same shape would have fired for every Store app on the
// machine.
func TestWhatsAppStoreAppDoesNotTripUnsignedRule(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	const image = `C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2627.101.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe`

	subj := Subject{
		// Exactly what the signature check reports for an MSIX package: not
		// signed, because the signature lives on the package, not this file.
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect, Signed: false},
		Conn:   ledger.Connection{Image: image, RemoteIP: "2a03:2880:f31e:120:face:b00c:0:167", RemotePort: 443},
		Domain: "media-atl3-3.cdn.whatsapp.net",
		Recon:  recon.Info{Org: "FACEBOOK", Country: "US"},
		HadDNS: true, FirstContact: true,
	}
	for _, id := range []string{"c2-unsigned-first-contact", "c2-raw-ip-no-dns"} {
		if d := find(e.Evaluate(subj), id); d != nil {
			t.Errorf("%s fired for a Microsoft Store app:\n%s", id, d.Rule.RenderNarrative(d.Fields))
		}
	}
}

// The exemption must not extend past the Store folder. An unsigned binary
// anywhere a user can write is still unvouched.
func TestUnsignedProgramOutsideTheStoreStillFires(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	subj := Subject{
		Event:  event.NormalizedEvent{Kind: event.KindNetConnect, Signed: false},
		Conn:   ledger.Connection{Image: `C:\Users\k\AppData\Local\Temp\sync-helper.exe`, RemoteIP: "203.0.113.9", RemotePort: 443},
		Domain: "somewhere.test",
		Recon:  recon.Info{Org: "SOME-SMALL-HOSTING-LLC", Country: "RU"},
		HadDNS: true, FirstContact: true,
	}
	if d := find(e.Evaluate(subj), "c2-unsigned-first-contact"); d == nil {
		t.Error("an unsigned program in Temp must still fire")
	}
}

// "System is reading your saved Edge passwords", with buttons offering to stop
// and quarantine it. PID 4 is the Windows kernel: ETW attributes cache-manager
// writeback of memory-mapped pages to it, so a browser dirtying a page and
// Windows flushing it later reads as the kernel touching the file.
func TestKernelIsNotAProgram(t *testing.T) {
	for _, name := range []string{"System", "system", " System ", "Registry", "Memory Compression", ""} {
		if !SystemProcess(name) {
			t.Errorf("%q should be recognised as the kernel, not a program", name)
		}
		if ActionableImage(name) {
			t.Errorf("%q must never be offered as something to stop or quarantine", name)
		}
	}
	for _, path := range []string{
		`C:\Program Files\BraveSoftware\brave.exe`,
		`C:\Users\k\AppData\Local\Temp\sync-helper.exe`,
	} {
		if SystemProcess(path) {
			t.Errorf("%s is a real program", path)
		}
		if !ActionableImage(path) {
			t.Errorf("%s should be actionable", path)
		}
	}
	// A bare name with no directory is not something a remediation can act on.
	if ActionableImage("svchost.exe") {
		t.Error("a bare executable name is not a path and cannot be quarantined")
	}
}

// The credential rule must not fire for the kernel at all.
func TestKernelDoesNotTripCredentialTheft(t *testing.T) {
	e := New(loadEveryPack(t), nil)
	dets := e.EvaluateFile(FileSubject{
		PID: 4, Image: "System",
		Path: `C:\Users\k\AppData\Local\Microsoft\Edge\User Data\Default\Login Data`,
	})
	if d := find(dets, "credential-theft"); d != nil {
		t.Errorf("the kernel tripped credential-theft:\n%s", d.Rule.RenderNarrative(d.Fields))
	}
}
