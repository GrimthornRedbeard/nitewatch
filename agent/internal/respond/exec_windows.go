// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package respond

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// WindowsExecutor performs remediation using ordinary Windows facilities.
type WindowsExecutor struct {
	// QuarantineDir is where quarantined files are moved. Kept beside the agent
	// so the user can find it, and so an uninstall does not strand files in a
	// location nobody knows about.
	QuarantineDir string
}

func NewWindowsExecutor(dir string) *WindowsExecutor {
	return &WindowsExecutor{QuarantineDir: dir}
}

func (w *WindowsExecutor) Execute(a Action) Result {
	switch a.Kind {
	case KillProcess:
		return w.kill(a)
	case BlockAddress:
		return w.block(a)
	case QuarantineFile:
		return w.quarantine(a)
	case RemoveAutostart:
		return w.removeAutostart(a)
	}
	return Result{Message: "unknown action"}
}

func (w *WindowsExecutor) Undo(a Action, undo map[string]string) Result {
	switch a.Kind {
	case BlockAddress:
		return w.unblock(undo)
	case QuarantineFile:
		return w.restore(undo)
	case RemoveAutostart:
		return w.restoreAutostart(undo)
	}
	return Result{Message: "this action cannot be undone"}
}

// kill terminates a process and its children. /T takes the tree, which matters:
// killing a dropper while its payload keeps running solves nothing.
func (w *WindowsExecutor) kill(a Action) Result {
	pid := a.Params["pid"]
	if pid == "" {
		return Result{Message: "no process id"}
	}
	out, err := exec.Command(system32("taskkill.exe"), "/PID", pid, "/T", "/F").CombinedOutput()
	if err != nil {
		return Result{Message: fmt.Sprintf("could not stop the program: %s", clean(out))}
	}
	return Result{OK: true, Message: fmt.Sprintf("Stopped %s and anything it started.", a.Params["name"])}
}

// block adds outbound and inbound firewall rules for an address. Both
// directions, because a C2 channel the malware initiated can be re-established
// from either end once the address is known to both.
func (w *WindowsExecutor) block(a Action) Result {
	ip := a.Params["ip"]
	if ip == "" {
		return Result{Message: "no address"}
	}
	name := ruleNameFor(ip)
	for _, dir := range []string{"out", "in"} {
		args := []string{"advfirewall", "firewall", "add", "rule",
			"name=" + name, "dir=" + dir, "action=block", "remoteip=" + ip}
		if out, err := exec.Command(system32("netsh.exe"), args...).CombinedOutput(); err != nil {
			return Result{Message: fmt.Sprintf("could not add the firewall rule: %s", clean(out))}
		}
	}
	return Result{
		OK:      true,
		Message: fmt.Sprintf("Blocked %s. Nothing on this PC can contact it until you undo this.", ip),
		Undo:    map[string]string{"rule": name, "ip": ip},
	}
}

func (w *WindowsExecutor) unblock(undo map[string]string) Result {
	name := undo["rule"]
	if name == "" {
		return Result{Message: "no rule recorded"}
	}
	if out, err := exec.Command(system32("netsh.exe"), "advfirewall", "firewall", "delete", "rule",
		"name="+name).CombinedOutput(); err != nil {
		return Result{Message: fmt.Sprintf("could not remove the firewall rule: %s", clean(out))}
	}
	return Result{OK: true, Message: fmt.Sprintf("Unblocked %s.", undo["ip"])}
}

// quarantine moves a file where it cannot run and strips execute permission.
// The original path is recorded so restore puts it back exactly.
func (w *WindowsExecutor) quarantine(a Action) Result {
	path := a.Params["path"]
	if path == "" {
		return Result{Message: "no file path"}
	}
	if InWindowsDir(path) {
		return Result{Message: "NiteWatch does not quarantine files inside the Windows folder"}
	}
	if _, err := os.Stat(path); err != nil {
		return Result{Message: "that file is no longer there"}
	}
	if err := os.MkdirAll(w.QuarantineDir, 0o700); err != nil {
		return Result{Message: "could not create the quarantine folder"}
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	dest := filepath.Join(w.QuarantineDir, stamp+"-"+filepath.Base(path)+".quarantined")

	if err := os.Rename(path, dest); err != nil {
		// Rename fails across volumes; copy then remove.
		if err := copyFile(path, dest); err != nil {
			return Result{Message: fmt.Sprintf("could not move the file: %v", err)}
		}
		if err := os.Remove(path); err != nil {
			return Result{Message: "copied the file to quarantine, but could not remove the original — it may still be running"}
		}
	}
	// Deny execution even from the quarantine folder.
	_ = exec.Command(system32("icacls.exe"), dest, "/deny", "*S-1-1-0:(X)").Run()

	// The quarantine folder is user-writable, so the file could be swapped
	// before an undo. Record what was quarantined; restore checks it.
	sum, err := hashFile(dest)
	if err != nil {
		return Result{OK: true, Message: fmt.Sprintf("Moved the program to quarantine (it cannot be restored automatically: %v). Original location: %s", err, path)}
	}
	return Result{
		OK:      true,
		Message: fmt.Sprintf("Moved the program to quarantine. Original location: %s", path),
		Undo:    map[string]string{"from": dest, "to": path, "sha256": sum},
	}
}

func (w *WindowsExecutor) restore(undo map[string]string) Result {
	if err := restoreFile(undo["from"], undo["to"], undo["sha256"]); err != nil {
		return Result{Message: fmt.Sprintf("could not restore the file: %v", err)}
	}
	return Result{OK: true, Message: fmt.Sprintf("Restored the program to %s.", undo["to"])}
}

// restoreFile puts a quarantined file back, elevated, without trusting the
// user-writable quarantine folder or the path on the way to the destination.
//
//  1. The quarantined file is opened with no write or delete sharing, so it
//     cannot be swapped while it is read, and its SHA-256 must equal the one
//     recorded (and sealed) when it was quarantined.
//  2. The destination folder is opened, again without delete sharing, and its
//     real path must equal the recorded one and lie outside the Windows folder.
//     That refuses a junction or symlink planted anywhere on the way, and
//     holding the handle keeps the folder from being swapped afterwards.
//  3. The bytes already verified are written to a NEW file: an existing file at
//     the destination is never overwritten.
//
// The restored file inherits the destination folder's permissions; it does not
// carry its original ACL or alternate data streams (including the
// downloaded-from-the-internet mark).
func restoreFile(from, to, wantSHA string) error {
	if from == "" || to == "" || wantSHA == "" {
		return fmt.Errorf("incomplete quarantine record")
	}
	src, err := openNoShareWrite(from, windows.GENERIC_READ)
	if err != nil {
		return fmt.Errorf("the quarantined file is missing or in use")
	}
	f := os.NewFile(uintptr(src), from)
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return err
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != strings.ToLower(wantSHA) {
		return fmt.Errorf("the quarantined file has changed since it was quarantined, so it will not be restored")
	}

	parent := filepath.Dir(to)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("could not recreate the original folder")
	}
	d, err := openRealDir(parent)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(d)

	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("something is already at %s; move it aside first", to)
		}
		return err
	}
	if _, err := out.Write(data); err != nil {
		out.Close()
		_ = os.Remove(to)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Remove(from)
	return nil
}

// openRealDir opens dir without delete sharing and checks that its final path,
// after every junction and symlink is resolved, is the path we were given and
// is not inside the Windows folder. The caller must close the handle, and
// should hold it for as long as it relies on the check.
func openRealDir(dir string) (windows.Handle, error) {
	// GENERIC_READ, not just FILE_READ_ATTRIBUTES: an open requesting only
	// attribute access is exempt from share-mode checks, so it would not stop
	// anyone renaming the folder while we rely on it.
	h, err := openNoShareWrite(dir, windows.GENERIC_READ)
	if err != nil {
		return 0, fmt.Errorf("could not open %s", dir)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil || int(n) >= len(buf) {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("could not resolve %s", dir)
	}
	final := strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`)
	if !samePath(final, dir) {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("%s is a link to somewhere else; refusing to act through it", dir)
	}
	if InWindowsDir(final) {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("refusing to act inside the Windows folder")
	}
	return h, nil
}

// openNoShareWrite opens a file or directory allowing others to read it but
// not to write, rename or delete it while the handle is open.
func openNoShareWrite(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	// No FILE_FLAG_OPEN_REPARSE_POINT: links must be FOLLOWED here, so that
	// openRealDir sees where a junctioned folder really leads. Opening the link
	// itself would report the link's own path and pass the check.
	// BACKUP_SEMANTICS is what allows a directory to be opened at all.
	return windows.CreateFile(p, access, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// removeAutostart deletes the registry value or startup file, recording what it
// held so the change can be reversed exactly.
func (w *WindowsExecutor) removeAutostart(a Action) Result {
	loc, name := a.Params["location"], a.Params["name"]
	if loc == "" || name == "" {
		return Result{Message: "no autostart entry recorded"}
	}

	// Startup-folder entries are files, not registry values.
	if !strings.HasPrefix(strings.ToUpper(loc), "HK") {
		src := filepath.Join(loc, name)
		if err := os.MkdirAll(w.QuarantineDir, 0o700); err != nil {
			return Result{Message: "could not create the quarantine folder"}
		}
		dest := filepath.Join(w.QuarantineDir, "startup-"+name)
		if err := os.Rename(src, dest); err != nil {
			return Result{Message: fmt.Sprintf("could not remove the startup item: %v", err)}
		}
		sum, err := hashFile(dest)
		if err != nil {
			return Result{OK: true, Message: "Removed it from your Startup folder (it cannot be restored automatically)."}
		}
		return Result{OK: true, Message: "Removed it from your Startup folder.",
			Undo: map[string]string{"kind": "file", "from": dest, "to": src, "sha256": sum}}
	}

	root, sub, err := splitRegistryPath(loc)
	if err != nil {
		return Result{Message: err.Error()}
	}
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return Result{Message: "could not open that startup setting (it may need Administrator)"}
	}
	defer k.Close()

	old, _, err := k.GetStringValue(name)
	if err != nil {
		return Result{Message: "that startup entry is already gone"}
	}
	if err := k.DeleteValue(name); err != nil {
		return Result{Message: fmt.Sprintf("could not remove the startup entry: %v", err)}
	}
	return Result{
		OK:      true,
		Message: fmt.Sprintf("Removed %q from startup. The program itself was not touched.", name),
		Undo:    map[string]string{"kind": "registry", "location": loc, "name": name, "value": old},
	}
}

func (w *WindowsExecutor) restoreAutostart(undo map[string]string) Result {
	switch undo["kind"] {
	case "file":
		if err := restoreFile(undo["from"], undo["to"], undo["sha256"]); err != nil {
			return Result{Message: fmt.Sprintf("could not restore the startup item: %v", err)}
		}
		return Result{OK: true, Message: "Restored the startup item."}
	case "registry":
		root, sub, err := splitRegistryPath(undo["location"])
		if err != nil {
			return Result{Message: err.Error()}
		}
		k, err := registry.OpenKey(root, sub, registry.SET_VALUE)
		if err != nil {
			return Result{Message: "could not open that startup setting"}
		}
		defer k.Close()
		if err := k.SetStringValue(undo["name"], undo["value"]); err != nil {
			return Result{Message: fmt.Sprintf("could not restore the startup entry: %v", err)}
		}
		return Result{OK: true, Message: "Restored the startup entry."}
	}
	return Result{Message: "no undo record"}
}

func splitRegistryPath(loc string) (registry.Key, string, error) {
	parts := strings.SplitN(loc, `\`, 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("unrecognised registry location")
	}
	switch strings.ToUpper(parts[0]) {
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, parts[1], nil
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, parts[1], nil
	}
	return 0, "", fmt.Errorf("unrecognised registry hive")
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

func clean(out []byte) string {
	return strings.Join(strings.Fields(string(out)), " ")
}

// system32 builds an absolute path under the real system directory. An elevated
// process must never resolve helper binaries through %PATH% — a user-writable
// directory on the path lets an unprivileged user plant netsh.exe or taskkill.exe
// and have this agent run it as SYSTEM.
func system32(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}
