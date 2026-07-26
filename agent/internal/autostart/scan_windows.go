//go:build windows

package autostart

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// registryLocations are the autostart keys worth watching. Ordered roughly by
// how commonly malware uses them.
//
// HKCU entries matter most for consumer machines: they need no administrator
// rights, which is exactly why the majority of consumer malware lives there.
var registryLocations = []struct {
	Root windowsRoot
	Path string
	Kind Kind
	// Value-name mode: for keys where each VALUE is an autostart entry.
	// Subkey mode (services, IFEO) is handled separately.
	Values bool
}{
	{rootCU, `Software\Microsoft\Windows\CurrentVersion\Run`, KindRunKey, true},
	{rootLM, `Software\Microsoft\Windows\CurrentVersion\Run`, KindRunKey, true},
	{rootCU, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, KindRunOnce, true},
	{rootLM, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, KindRunOnce, true},
	{rootLM, `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`, KindRunKey, true},
	{rootLM, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, KindWinlogon, true},
	{rootLM, `Software\Microsoft\Windows NT\CurrentVersion\Windows`, KindAppInit, true},
}

type windowsRoot int

const (
	rootCU windowsRoot = iota
	rootLM
)

func (r windowsRoot) key() registry.Key {
	if r == rootLM {
		return registry.LOCAL_MACHINE
	}
	return registry.CURRENT_USER
}

func (r windowsRoot) name() string {
	if r == rootLM {
		return "HKLM"
	}
	return "HKCU"
}

// winlogonValues are the only Winlogon values that launch code. The key holds
// many unrelated settings, and reporting all of them would be noise.
var winlogonValues = map[string]bool{"shell": true, "userinit": true, "taskman": true}

// Scan collects the current autostart configuration.
//
// Errors are swallowed per location: a key we cannot read (permissions, or it
// simply does not exist on this SKU) must not cost us visibility into the rest.
func Scan() (Snapshot, error) {
	var out []Entry

	for _, loc := range registryLocations {
		k, err := registry.OpenKey(loc.Root.key(), loc.Path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := k.ReadValueNames(0)
		if err != nil {
			k.Close()
			continue
		}
		for _, name := range names {
			// Winlogon and AppInit keys hold mostly unrelated settings.
			switch loc.Kind {
			case KindWinlogon:
				if !winlogonValues[strings.ToLower(name)] {
					continue
				}
			case KindAppInit:
				if !strings.EqualFold(name, "AppInit_DLLs") {
					continue
				}
			}
			val, _, err := k.GetStringValue(name)
			if err != nil || strings.TrimSpace(val) == "" {
				continue
			}
			out = append(out, Entry{
				Kind:     loc.Kind,
				Location: loc.Root.name() + `\` + loc.Path,
				Name:     name,
				Target:   val,
			})
		}
		k.Close()
	}

	out = append(out, scanIFEO()...)
	out = append(out, scanStartupFolders()...)
	return Snapshot{Entries: out}, nil
}

// scanIFEO finds Image File Execution Options debuggers — a mechanism that
// launches an attacker's program whenever a chosen program is started.
// Legitimate software essentially never sets this.
func scanIFEO() []Entry {
	const base = `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer root.Close()

	names, err := root.ReadSubKeyNames(0)
	if err != nil {
		return nil
	}
	var out []Entry
	for _, name := range names {
		sub, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if dbg, _, err := sub.GetStringValue("Debugger"); err == nil && strings.TrimSpace(dbg) != "" {
			out = append(out, Entry{
				Kind:     KindIFEO,
				Location: `HKLM\` + base + `\` + name,
				Name:     name,
				Target:   dbg,
			})
		}
		sub.Close()
	}
	return out
}

// scanStartupFolders finds shortcuts and executables dropped into the Startup
// folders, which run at sign-in without touching the registry at all.
func scanStartupFolders() []Entry {
	var dirs []string
	if appData := os.Getenv("APPDATA"); appData != "" {
		dirs = append(dirs, filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	if progData := os.Getenv("ProgramData"); progData != "" {
		dirs = append(dirs, filepath.Join(progData, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}

	var out []Entry
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			out = append(out, Entry{
				Kind:     KindStartupFolder,
				Location: dir,
				Name:     e.Name(),
				Target:   filepath.Join(dir, e.Name()),
			})
		}
	}
	return out
}
