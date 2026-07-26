// Package filewatch classifies file activity and spots the shapes that matter:
// mass encryption, and programs reading secrets they have no business reading.
//
// Volume is the design constraint. File I/O is by far the noisiest thing an
// operating system does — a single build or virus scan writes tens of thousands
// of files. Everything here is built to discard the ordinary as early and as
// cheaply as possible, because a detector that cannot keep up is a detector
// that misses the event that mattered.
package filewatch

import (
	"path/filepath"
	"strings"
)

// Category is why a path is interesting, if it is.
type Category int

const (
	// Ignored is the overwhelming majority: build output, caches, temp churn.
	Ignored Category = iota
	// UserDocument is irreplaceable personal data — the target of ransomware.
	UserDocument
	// Credential is a secret store: browser passwords, SSH keys, wallets.
	Credential
	// RansomNote is a file whose name matches the note ransomware leaves.
	RansomNote
)

// documentExts are the file types people cannot replace. Deliberately narrow:
// this list decides what "your files are being encrypted" means, and including
// build artefacts would make the signal meaningless.
var documentExts = map[string]bool{
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".pdf": true, ".txt": true, ".rtf": true, ".odt": true, ".ods": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".heic": true,
	".raw": true, ".cr2": true, ".nef": true, ".psd": true,
	".mp3": true, ".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".wav": true,
	".zip": true, ".rar": true, ".7z": true,
	".csv": true, ".json": true, ".xml": true, ".md": true,
	".pst": true, ".ost": true, ".mdb": true, ".accdb": true, ".sql": true, ".db": true,
}

// userDirs are where irreplaceable data lives. A process rewriting files here
// is doing something very different from one rewriting its own cache.
var userDirs = []string{
	`\documents\`, `\desktop\`, `\pictures\`, `\videos\`, `\music\`,
	`\downloads\`, `\onedrive\`, `\dropbox\`, `\google drive\`,
}

// credentialPaths are secret stores. Reading these is normal for the program
// that owns them and deeply abnormal for anything else — which is why the
// detector compares the reader against the owner rather than alerting on the
// path alone.
var credentialPaths = []struct {
	Fragment string
	What     string
	Owner    string // the process expected to read it, "" if many
}{
	{`\google\chrome\user data\default\login data`, "your saved Chrome passwords", "chrome.exe"},
	{`\google\chrome\user data\default\cookies`, "your Chrome cookies", "chrome.exe"},
	{`\bravesoftware\brave-browser\user data\default\login data`, "your saved Brave passwords", "brave.exe"},
	{`\microsoft\edge\user data\default\login data`, "your saved Edge passwords", "msedge.exe"},
	{`\mozilla\firefox\profiles\`, "your Firefox profile, which stores saved passwords", "firefox.exe"},
	{`\.ssh\id_`, "your SSH private key", ""},
	{`\.aws\credentials`, "your AWS access keys", ""},
	{`\.config\gcloud\`, "your Google Cloud credentials", ""},
	{`\.kube\config`, "your Kubernetes credentials", ""},
	{`\appdata\roaming\bitcoin\wallet.dat`, "your Bitcoin wallet", ""},
	{`\appdata\roaming\ethereum\keystore`, "your Ethereum keystore", ""},
	{`\appdata\roaming\exodus\`, "your Exodus crypto wallet", ""},
	{`\appdata\local\packages\microsoft.windows.cloudexperiencehost`, "", ""}, // excluded below
	{`\appdata\roaming\discord\local storage`, "your Discord session tokens", "discord.exe"},
	{`\appdata\roaming\telegram desktop\tdata`, "your Telegram session", "telegram.exe"},
	{`\keepass`, "your KeePass password database", ""},
	{`.kdbx`, "your KeePass password database", ""},
}

// ransomNoteNames are the filenames ransomware leaves behind. Matching these is
// a late signal — the damage is done — but it removes all doubt about what is
// happening, which changes the advice from "check this" to "act now".
var ransomNoteNames = []string{
	"readme.txt", "read_me.txt", "readme.html", "how_to_decrypt", "how-to-decrypt",
	"decrypt_instruction", "decrypt-instructions", "your_files", "restore_files",
	"recovery_key", "recover_files", "!!!readme", "_readme.txt", "how_to_back_files",
}

// Classify decides what kind of file a path is.
func Classify(path string) Category {
	if path == "" {
		return Ignored
	}
	p := strings.ToLower(filepath.ToSlash(path))
	p = strings.ReplaceAll(p, "/", `\`)

	base := p
	if i := strings.LastIndex(p, `\`); i >= 0 {
		base = p[i+1:]
	}

	// Credential stores are recognised anywhere: their paths are specific.
	if what, _ := CredentialInfo(path); what != "" {
		return Credential
	}

	// A ransom note only counts INSIDE the folders ransomware targets. Matching
	// "readme.txt" anywhere on disk made every source checkout and unzipped
	// archive raise the loudest alert in the product — and since a note alone
	// satisfied Confirmed, one file write was enough.
	if inUserDir(p) {
		for _, n := range ransomNoteNames {
			if strings.Contains(base, n) {
				return RansomNote
			}
		}
	}
	if !inUserDir(p) {
		return Ignored
	}
	// A document by its own extension...
	if documentExts[filepath.Ext(base)] {
		return UserDocument
	}
	// ...or one that WAS a document until something renamed it.
	//
	// This case is the whole point. Ransomware encrypts taxes.xlsx and writes
	// taxes.xlsx.locked, so testing the current extension alone makes every
	// encrypted file invisible to the detector — it would then only ever fire
	// on the ransom note, which arrives after the damage is done.
	if EncryptedLookingExt(path) {
		return UserDocument
	}
	return Ignored
}

// CredentialInfo reports what secret a path holds and which program legitimately
// reads it.
func CredentialInfo(path string) (what, owner string) {
	p := strings.ToLower(filepath.ToSlash(path))
	p = strings.ReplaceAll(p, "/", `\`)
	for _, c := range credentialPaths {
		if c.What == "" {
			continue // placeholder exclusions
		}
		if strings.Contains(p, c.Fragment) {
			return c.What, c.Owner
		}
	}
	return "", ""
}

func inUserDir(lowerPath string) bool {
	for _, d := range userDirs {
		if strings.Contains(lowerPath, d) {
			return true
		}
	}
	return false
}

// EncryptedLookingExt reports whether a file's extension looks like ransomware
// output: an unfamiliar extension appended to a document.
//
// Heuristic, and honest about it: the caller pairs it with a burst of writes
// before drawing any conclusion. On its own it would flag every unusual file
// type a person happens to own.
func EncryptedLookingExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" || len(ext) > 12 {
		return false
	}
	if documentExts[ext] {
		return false
	}
	// Known-benign extensions that appear in user folders constantly.
	switch ext {
	case ".tmp", ".ini", ".lnk", ".url", ".log", ".bak", ".part", ".crdownload",
		".ds_store", ".thumbs", ".exe", ".dll", ".sys", ".dat", ".idx", ".lock":
		return false
	}
	// A double extension over a document is the classic shape: report.docx.locked
	trimmed := strings.TrimSuffix(strings.ToLower(path), ext)
	return documentExts[filepath.Ext(trimmed)]
}

// ShadowCopyTool reports whether an image is one of the tools ransomware uses to
// destroy backups before demanding payment. Running these is not proof of
// anything on its own — administrators use them legitimately — but during a
// burst of file writes it removes all doubt.
func ShadowCopyTool(image string) bool {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(image, `\`, "/")))
	switch base {
	case "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe":
		return true
	}
	return false
}
