// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package detect

import "testing"

const sshKey = `C:\Users\kstal\.ssh\id_ed25519_devbox`

// The single alert a 16-day soak on a working desktop produced.
//
// It was correct: claude.exe really did read the key. It was also Kevin's own
// tooling connecting to his dev box, 136 times, and the causal graph was
// holding that explanation while the alert called it information-stealer
// behaviour.
func TestReadingAnSSHKeyYouThenUseIsNotTheft(t *testing.T) {
	subj := FileSubject{
		Image:  `C:\Program Files\WindowsApps\Claude\app\claude.exe`,
		Path:   sshKey,
		Signed: true, Signer: "Anthropic PBC",
		SSHPeers: []string{"192.168.1.69"},
	}
	if got := detectCredentialTheft(subj); got != nil {
		t.Errorf("still reported as credential theft: %v", got)
	}
	// Not silenced — handed to the quieter rule, which still names the file.
	got := detectSSHKeyInUse(subj)
	if got == nil {
		t.Fatal("nothing reported at all; the user should still learn the key was read")
	}
	if got["SSHPeer"] != "192.168.1.69" {
		t.Errorf("SSHPeer = %v, want the host it actually reached", got["SSHPeer"])
	}
	if got["SecretDescription"] == "" {
		t.Error("no description of what was read")
	}
}

// Reading the key WITHOUT using it is the alert the rule exists for, and the
// case an information stealer produces. It must survive untouched.
func TestReadingAnSSHKeyWithoutUsingItIsStillCritical(t *testing.T) {
	subj := FileSubject{
		Image: `C:\Users\kstal\AppData\Local\Temp\sync-helper.exe`,
		Path:  sshKey,
	}
	if got := detectCredentialTheft(subj); got == nil {
		t.Error("a program that read an SSH key and never used it was suppressed")
	}
	if got := detectSSHKeyInUse(subj); got != nil {
		t.Errorf("the quiet rule fired without any SSH connection: %v", got)
	}
}

// The pass is for SSH keys specifically. Speaking SSH must not buy silence on
// a browser password store — otherwise "open a connection to port 22" becomes
// a way to read anything.
func TestSpeakingSSHDoesNotExcuseReadingOtherSecrets(t *testing.T) {
	subj := FileSubject{
		Image:    `C:\Users\kstal\AppData\Local\Temp\sync-helper.exe`,
		Path:     `C:\Users\kstal\AppData\Local\Google\Chrome\User Data\Default\Login Data`,
		SSHPeers: []string{"192.168.1.69"},
	}
	if got := detectCredentialTheft(subj); got == nil {
		t.Error("an SSH connection silenced a Chrome password-store read")
	}
}

// An unsigned stranger that reads the key and then uses it is still a downgrade
// under this rule, which is a deliberate limit worth stating: the suppression
// keys on demonstrated USE, not on who is doing it. An attacker who wants it
// has to actually establish SSH sessions rather than merely rename themselves —
// and the quieter alert still names the program and the host it reached.
func TestTheDowngradeKeysOnUseNotOnIdentity(t *testing.T) {
	got := detectSSHKeyInUse(FileSubject{
		Image:    `C:\Users\kstal\AppData\Local\Temp\whatever.exe`,
		Path:     sshKey,
		SSHPeers: []string{"203.0.113.9"},
	})
	if got == nil {
		t.Fatal("expected the quieter rule to fire")
	}
	if got["SSHPeer"] != "203.0.113.9" {
		t.Errorf("the host reached must be named so it can be judged: %v", got["SSHPeer"])
	}
}
