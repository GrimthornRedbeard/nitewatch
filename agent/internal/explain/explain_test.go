package explain

import (
	"strings"
	"testing"
)

func TestForImageMatchesRealPaths(t *testing.T) {
	cases := map[string]string{
		`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`:                "Brave",
		`C:\Users\kstal\AppData\Local\Discord\app-1.0.9249\Discord.exe`:                     "Discord",
		`C:\Windows\System32\svchost.exe`:                                                   "Windows Service Host",
		`C:\Windows\System32\wscript.exe`:                                                   "Windows Script Host",
		`C:\Program Files\WindowsApps\Claude_1.24012.9.0_x64__pzs8sxrjxfjjc\app\claude.exe`: "Claude",
	}
	for image, want := range cases {
		p, ok := ForImage(image)
		if !ok {
			t.Errorf("%s: no description", image)
			continue
		}
		if p.Name != want {
			t.Errorf("%s: name = %q, want %q", image, p.Name, want)
		}
	}
}

// A wrong guess is a confident lie to somebody with no way to check it. When we
// do not know, we say nothing.
func TestUnknownProgramsReturnNothing(t *testing.T) {
	for _, image := range []string{
		`C:\Users\k\AppData\Local\Temp\sync-helper.exe`,
		`C:\Users\k\Downloads\invoice.exe`,
		`C:\weird\zzzz.exe`,
		``,
	} {
		if p, ok := ForImage(image); ok {
			t.Errorf("%s: invented a description: %+v", image, p)
		}
	}
}

// Every entry has to read as something a person would say out loud.
func TestEveryDescriptionIsPlainAndComplete(t *testing.T) {
	jargon := []string{"executable", "binary", "daemon", "runtime", "protocol", "subsystem"}
	for key, p := range programs {
		if p.Name == "" || p.What == "" {
			t.Errorf("%s: missing name or description", key)
		}
		if !strings.HasSuffix(strings.TrimSpace(p.What), ".") &&
			!strings.HasSuffix(strings.TrimSpace(p.What), ".)") {
			t.Errorf("%s: description should be a sentence: %q", key, p.What)
		}
		if strings.HasSuffix(p.Name, ".exe") {
			t.Errorf("%s: Name is what a person calls it, not the filename: %q", key, p.Name)
		}
		low := strings.ToLower(p.What)
		for _, j := range jargon {
			if strings.Contains(low, j) {
				t.Errorf("%s: description uses jargon %q: %q", key, j, p.What)
			}
		}
	}
}

func TestTermsAreDefinedPlainly(t *testing.T) {
	for key, tm := range terms {
		if tm.Term == "" || tm.Short == "" || tm.Long == "" {
			t.Errorf("%s: incomplete definition", key)
		}
		if len(tm.Short) > 90 {
			t.Errorf("%s: short form is for a tooltip, keep it short (%d chars)", key, len(tm.Short))
		}
	}
	for _, k := range []string{"pid", "ip", "port"} {
		if _, ok := ForTerm(k); !ok {
			t.Errorf("%q must be defined", k)
		}
	}
}

func TestSystemProgramsAreMarked(t *testing.T) {
	for _, k := range []string{"svchost.exe", "explorer.exe", "lsass.exe", "dwm.exe"} {
		if !programs[k].System {
			t.Errorf("%s should be marked as part of Windows", k)
		}
	}
	if programs["brave.exe"].System {
		t.Error("brave.exe is not part of Windows")
	}
}
