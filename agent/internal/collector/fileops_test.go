// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/threattape/nitewatch/agent/internal/detect"
	"github.com/threattape/nitewatch/agent/internal/intel"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/rules"
	"github.com/threattape/nitewatch/agent/internal/source"
)

func engineWithAllPacks(t *testing.T) *detect.Engine {
	t.Helper()
	var packs []*rules.Pack
	for _, f := range []string{"ransomware.yaml", "credentials.yaml", "c2.yaml", "persistence.yaml"} {
		data, err := os.ReadFile(filepath.Join("../../rules", f))
		if err != nil {
			t.Fatal(err)
		}
		p, err := rules.LoadPack(data)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		packs = append(packs, p)
	}
	return detect.New(rules.NewSet(packs...), intel.New())
}

func runTrace(t *testing.T, lines []string) *ledger.DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { led.Close() })

	src, err := source.NewReplaySource(path)
	if err != nil {
		t.Fatal(err)
	}
	c := NewWithOptions(src, led, Options{Detect: engineWithAllPacks(t)})
	if err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	return led
}

// Reported from a live machine: opening Brave's "upload a picture" dialog on a
// folder of photos raised a ransomware alert about 100+ modified files.
//
// The shell reads and thumbnails every image in the folder. Those are READS.
// Every Kernel-File event was being classified as a write, so choosing a file
// to upload looked identical to encrypting the folder.
func TestFilePickerReadingPhotosIsNotRansomware(t *testing.T) {
	var lines []string
	lines = append(lines, `{"seq":1,"kind":"ProcStart","time":"2026-07-26T18:00:00Z","pid":900,"image":"C:\\Program Files\\BraveSoftware\\brave.exe"}`)
	for i := 0; i < 120; i++ {
		lines = append(lines, fmt.Sprintf(
			`{"seq":%d,"kind":"FileRead","time":"2026-07-26T18:00:%02dZ","pid":900,`+
				`"image":"C:\\Program Files\\BraveSoftware\\brave.exe",`+
				`"path":"C:\\Users\\k\\Pictures\\holiday\\IMG_%04d.jpg"}`, i+2, i%60, i))
	}

	led := runTrace(t, lines)
	alerts, err := led.RecentAlerts(50)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if strings.HasPrefix(a.RuleID, "ransomware") {
			t.Errorf("reading %d photos raised %s: %s", 120, a.RuleID, a.Title)
		}
	}
}

// The real thing must still be caught: the same volume, but WRITES.
func TestWritingTheSameFilesStillAlerts(t *testing.T) {
	var lines []string
	lines = append(lines, `{"seq":1,"kind":"ProcStart","time":"2026-07-26T18:00:00Z","pid":901,"image":"C:\\Users\\k\\Downloads\\evil.exe"}`)
	for i := 0; i < 60; i++ {
		lines = append(lines, fmt.Sprintf(
			`{"seq":%d,"kind":"FileWrite","time":"2026-07-26T18:00:%02dZ","pid":901,`+
				`"image":"C:\\Users\\k\\Downloads\\evil.exe",`+
				`"path":"C:\\Users\\k\\Documents\\d%d\\report%d.docx.locked"}`, i+2, i%60, i%5, i))
	}

	led := runTrace(t, lines)
	alerts, _ := led.RecentAlerts(50)
	var found bool
	for _, a := range alerts {
		if strings.HasPrefix(a.RuleID, "ransomware") {
			found = true
		}
	}
	if !found {
		t.Fatal("an actual encryption sweep must still be detected")
	}
}

// Credential theft is a READ, so that path must survive the split.
func TestReadingACredentialStoreStillAlerts(t *testing.T) {
	lines := []string{
		`{"seq":1,"kind":"ProcStart","time":"2026-07-26T18:00:00Z","pid":902,"image":"C:\\Users\\k\\Downloads\\stealer.exe"}`,
		`{"seq":2,"kind":"FileRead","time":"2026-07-26T18:00:01Z","pid":902,` +
			`"image":"C:\\Users\\k\\Downloads\\stealer.exe",` +
			`"path":"C:\\Users\\k\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"}`,
	}
	led := runTrace(t, lines)
	alerts, _ := led.RecentAlerts(50)
	var found bool
	for _, a := range alerts {
		if a.RuleID == "credential-theft" {
			found = true
		}
	}
	if !found {
		t.Fatal("reading a password store must still alert — that path is a READ")
	}
}
