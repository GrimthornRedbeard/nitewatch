// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package explain turns the jargon on the dashboard into plain English.
//
// The product's promise is that somebody who does not work in security can read
// what their computer is doing. A table full of PIDs, ports and executable names
// does not deliver that on its own: "brave.exe" means nothing to a person who
// only ever sees a lion on their taskbar, and "PID" means nothing to anyone
// outside the trade.
//
// Two kinds of help live here:
//
//   - Programs: what a given executable actually is, in one sentence a person
//     would say out loud. "Brave is a web browser, like Chrome or Edge."
//   - Terms: what the column headings mean. "A port is like an apartment number."
//
// Both are plain data, deliberately. This is a lookup table, not a
// classification engine — a wrong guess here is a confident lie to somebody who
// has no way to check it, so an entry exists only when we actually know.
// Anything not listed returns nothing and the UI stays quiet rather than
// inventing a description.
package explain

import (
	"path/filepath"
	"strings"
)

// Program is a plain-English account of one executable.
type Program struct {
	// Name is what a person calls it: "Brave", not "brave.exe".
	Name string `json:"name"`
	// What it is, in one sentence, assuming no technical knowledge.
	What string `json:"what"`
	// Publisher is who makes it, when that is not obvious from the name.
	Publisher string `json:"publisher,omitempty"`
	// Expected describes traffic that is normal for this program, so a person
	// can tell "this is fine" from "this is odd" without asking anyone.
	Expected string `json:"expected,omitempty"`
	// System marks parts of Windows itself. These alarm people
	// disproportionately because the names are cryptic and they are everywhere.
	System bool `json:"system,omitempty"`
}

// programs maps a lowercase executable name to its description.
//
// Keyed on filename rather than full path because the same program lives in
// different places on different machines. That is a real weakness — malware can
// name itself chrome.exe — so the UI presents this as "what a program with this
// name usually is", never as an identity check, and the alerting path does not
// consult it at all.
var programs = map[string]Program{
	// ── Browsers ────────────────────────────────────────────────────────
	"chrome.exe":   {Name: "Google Chrome", What: "A web browser — the program you use to visit websites.", Publisher: "Google", Expected: "Talks to a great many different sites, constantly. That is what a browser does."},
	"msedge.exe":   {Name: "Microsoft Edge", What: "A web browser, the one that comes with Windows.", Publisher: "Microsoft", Expected: "Talks to many sites. Windows also uses it quietly for things like help pages."},
	"firefox.exe":  {Name: "Firefox", What: "A web browser, made by a non-profit.", Publisher: "Mozilla", Expected: "Talks to many different sites."},
	"brave.exe":    {Name: "Brave", What: "A web browser, like Chrome or Edge, with ad-blocking built in.", Publisher: "Brave Software", Expected: "Talks to many different sites."},
	"opera.exe":    {Name: "Opera", What: "A web browser.", Publisher: "Opera", Expected: "Talks to many different sites."},
	"iexplore.exe": {Name: "Internet Explorer", What: "Microsoft's old web browser. Very little should still be using it.", Publisher: "Microsoft"},

	// ── Chat, mail, meetings ────────────────────────────────────────────
	"discord.exe":     {Name: "Discord", What: "A chat app, mostly used for gaming and communities.", Publisher: "Discord", Expected: "Stays connected all the time so messages arrive instantly."},
	"slack.exe":       {Name: "Slack", What: "A chat app used for work.", Publisher: "Salesforce", Expected: "Stays connected all the time."},
	"teams.exe":       {Name: "Microsoft Teams", What: "A work chat and video-meeting app.", Publisher: "Microsoft", Expected: "Stays connected all the time; uses a lot of data during calls."},
	"outlook.exe":     {Name: "Outlook", What: "An email program.", Publisher: "Microsoft", Expected: "Checks for new mail on a regular schedule."},
	"thunderbird.exe": {Name: "Thunderbird", What: "An email program.", Publisher: "Mozilla", Expected: "Checks for new mail on a schedule."},
	"zoom.exe":        {Name: "Zoom", What: "A video-meeting app.", Publisher: "Zoom", Expected: "Uses a lot of data during a meeting, and almost none otherwise."},
	"whatsapp.exe":    {Name: "WhatsApp", What: "A messaging app.", Publisher: "Meta", Expected: "Stays connected so messages arrive instantly."},
	"telegram.exe":    {Name: "Telegram", What: "A messaging app.", Publisher: "Telegram", Expected: "Stays connected all the time."},
	"signal.exe":      {Name: "Signal", What: "A private messaging app.", Publisher: "Signal Foundation", Expected: "Stays connected all the time."},

	// ── Media ───────────────────────────────────────────────────────────
	"spotify.exe": {Name: "Spotify", What: "A music streaming app.", Publisher: "Spotify", Expected: "Downloads a lot of data while music is playing."},
	"vlc.exe":     {Name: "VLC", What: "A video player.", Publisher: "VideoLAN", Expected: "Usually offline, unless you are streaming something."},

	// ── Files and sync ──────────────────────────────────────────────────
	"onedrive.exe":        {Name: "OneDrive", What: "Microsoft's file-syncing service — it keeps a copy of your files online.", Publisher: "Microsoft", Expected: "Uploads and downloads whenever your files change. Touching many files at once is its normal job."},
	"dropbox.exe":         {Name: "Dropbox", What: "A file-syncing service — it keeps a copy of your files online.", Publisher: "Dropbox", Expected: "Uploads and downloads whenever your files change."},
	"googledrivesync.exe": {Name: "Google Drive", What: "A file-syncing service.", Publisher: "Google", Expected: "Uploads and downloads whenever your files change."},

	// ── Gaming ──────────────────────────────────────────────────────────
	"steam.exe":             {Name: "Steam", What: "A shop and launcher for computer games.", Publisher: "Valve", Expected: "Checks for game updates constantly, and downloads a great deal when one arrives."},
	"steamwebhelper.exe":    {Name: "Steam (browser part)", What: "The part of Steam that displays the shop and web pages inside it.", Publisher: "Valve", Expected: "Behaves like a browser, because it is one."},
	"epicgameslauncher.exe": {Name: "Epic Games Launcher", What: "A shop and launcher for computer games.", Publisher: "Epic Games", Expected: "Checks for updates on a schedule."},
	"agent.exe":             {Name: "Battle.net Agent", What: "The part of Blizzard's game launcher that downloads updates. (Note: other programs also use the name \"Agent\".)", Publisher: "Blizzard", Expected: "Checks for game updates on a schedule."},

	// ── Development / AI ────────────────────────────────────────────────
	"claude.exe": {Name: "Claude", What: "An AI assistant app.", Publisher: "Anthropic", Expected: "Talks to its own servers whenever you send a message, and checks in regularly in between."},
	"code.exe":   {Name: "Visual Studio Code", What: "A program for writing computer code.", Publisher: "Microsoft", Expected: "Checks for updates, and downloads add-ons when you install them."},
	"git.exe":    {Name: "Git", What: "A tool programmers use to store and share code."},
	"python.exe": {Name: "Python", What: "A programming language. Something on this computer is running a program written in it."},
	"node.exe":   {Name: "Node.js", What: "A tool that runs programs written in JavaScript. Many desktop apps use it internally."},

	// ── Windows itself ──────────────────────────────────────────────────
	// These are the ones that frighten people most, because the names look
	// like nothing and there are dozens of them.
	"svchost.exe":            {Name: "Windows Service Host", System: true, What: "Part of Windows itself. It runs many of Windows' own background jobs, so it appears constantly and talks to Microsoft a lot.", Publisher: "Microsoft", Expected: "Very common. Seeing it talk to Microsoft addresses is normal."},
	"explorer.exe":           {Name: "Windows Explorer", System: true, What: "Part of Windows itself — your desktop, taskbar and file windows. It is running the whole time you are logged in.", Publisher: "Microsoft"},
	"lsass.exe":              {Name: "Windows Security Service", System: true, What: "Part of Windows itself. It handles signing in and passwords.", Publisher: "Microsoft"},
	"services.exe":           {Name: "Windows Service Manager", System: true, What: "Part of Windows itself. It starts and stops background jobs.", Publisher: "Microsoft"},
	"taskhostw.exe":          {Name: "Windows Task Host", System: true, What: "Part of Windows itself. It runs scheduled background jobs.", Publisher: "Microsoft"},
	"searchindexer.exe":      {Name: "Windows Search", System: true, What: "Part of Windows itself. It reads your files so you can search them quickly — which is why it touches a lot of files.", Publisher: "Microsoft", Expected: "Reads many files. That is the job."},
	"msmpeng.exe":            {Name: "Microsoft Defender", System: true, What: "The antivirus built into Windows. It reads files to check them for viruses.", Publisher: "Microsoft", Expected: "Reads a great many files, and downloads updated virus definitions."},
	"wuauclt.exe":            {Name: "Windows Update", System: true, What: "Part of Windows itself. It downloads Windows updates.", Publisher: "Microsoft"},
	"dwm.exe":                {Name: "Desktop Window Manager", System: true, What: "Part of Windows itself. It draws the windows on your screen.", Publisher: "Microsoft"},
	"runtimebroker.exe":      {Name: "Runtime Broker", System: true, What: "Part of Windows itself. It checks what apps are allowed to do.", Publisher: "Microsoft"},
	"backgroundtaskhost.exe": {Name: "Background Task Host", System: true, What: "Part of Windows itself. It runs small background jobs for apps.", Publisher: "Microsoft"},
	"ctfmon.exe":             {Name: "Windows Text Input", System: true, What: "Part of Windows itself. It handles typing, handwriting and languages.", Publisher: "Microsoft"},
	"conhost.exe":            {Name: "Console Window Host", System: true, What: "Part of Windows itself. It draws the black command-prompt windows.", Publisher: "Microsoft"},
	"sihost.exe":             {Name: "Shell Infrastructure Host", System: true, What: "Part of Windows itself. It runs parts of the Start menu and taskbar.", Publisher: "Microsoft"},
	"spoolsv.exe":            {Name: "Print Spooler", System: true, What: "Part of Windows itself. It manages printing.", Publisher: "Microsoft"},

	// ── Scripting hosts: worth naming because malware leans on them ─────
	"powershell.exe": {Name: "PowerShell", System: true, What: "A tool built into Windows for running commands and scripts. Useful to administrators — and popular with malware, because it is already installed.", Publisher: "Microsoft", Expected: "If you did not start this yourself, and you do not write scripts, it is worth a look."},
	"pwsh.exe":       {Name: "PowerShell", System: true, What: "A tool for running commands and scripts.", Publisher: "Microsoft"},
	"cmd.exe":        {Name: "Command Prompt", System: true, What: "The black window for typing commands, built into Windows.", Publisher: "Microsoft"},
	"wscript.exe":    {Name: "Windows Script Host", System: true, What: "A tool built into Windows for running small scripts. Rarely started on purpose by a person, and often used by malware arriving in an email attachment.", Publisher: "Microsoft", Expected: "If you did not expect this, it is worth a look."},
	"cscript.exe":    {Name: "Windows Script Host", System: true, What: "A tool built into Windows for running small scripts. Often used by malware.", Publisher: "Microsoft"},
	"mshta.exe":      {Name: "Microsoft HTML Application Host", System: true, What: "A little-used Windows tool that runs web pages as if they were programs. Malware uses it far more often than people do.", Publisher: "Microsoft"},
	"rundll32.exe":   {Name: "Windows Library Runner", System: true, What: "A Windows tool that runs code from a shared library. Windows uses it legitimately; so does malware, to hide.", Publisher: "Microsoft"},
	"regsvr32.exe":   {Name: "Windows Component Registrar", System: true, What: "A Windows tool for registering components. Sometimes abused to run malicious code.", Publisher: "Microsoft"},
}

// ForImage returns the description for an executable path, and whether one
// exists. Matching is on the filename, lowercased.
func ForImage(image string) (Program, bool) {
	if image == "" {
		return Program{}, false
	}
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(image, `\`, "/")))
	p, ok := programs[base]
	return p, ok
}

// Term is a plain-English definition of a piece of jargon on screen.
type Term struct {
	Term  string `json:"term"`
	Short string `json:"short"` // one line, for a tooltip
	Long  string `json:"long"`  // the fuller answer, with the analogy
}

// terms defines every technical word the dashboard shows.
//
// Analogies are chosen to be honest rather than cute. A port really is like an
// apartment number; an IP address really is like a street address. Where an
// analogy would mislead, there isn't one.
var terms = map[string]Term{
	"pid": {Term: "PID", Short: "A number Windows gives each running program.",
		Long: "Short for \"process ID\". Every time a program starts, Windows gives it a number so it can tell them apart — useful if the same program is running twice. The number changes each time the program starts, and means nothing on its own."},
	"ip": {Term: "IP address", Short: "The address of a computer on the internet.",
		Long: "Like a street address, but for computers. Every machine on the internet has one, and anything your computer talks to has one. They look like 93.184.216.34, or like 2607:6bc0::10 in the newer style."},
	"port": {Term: "Port", Short: "Which service on the far computer is being used.",
		Long: "If the IP address is the street address of a building, the port is the apartment number — it says which service inside that computer is being talked to. Port 443 means an encrypted web connection, which is the overwhelming majority of normal traffic."},
	"domain": {Term: "Domain name", Short: "The readable name of a website or service.",
		Long: "The human-readable name for an address, like google.com. Computers look the name up to find the number. A connection with no name is not automatically suspicious, but it is less accountable — there is no owner listed."},
	"dns": {Term: "DNS lookup", Short: "Asking \"what address does this name have?\"",
		Long: "Before your computer can talk to example.com, it has to ask what number that name corresponds to. That question is a DNS lookup. Seeing one tells us the program asked for a destination by name, rather than dialling a bare number."},
	"tcp": {Term: "TCP / UDP", Short: "Two different ways of sending data.",
		Long: "Two methods computers use to send data. TCP checks everything arrives; UDP is faster but does not check, so it suits video calls and games. Neither is more or less safe than the other."},
	"asn": {Term: "Owner", Short: "The company that runs the far end of the connection.",
		Long: "Blocks of internet addresses are registered to organisations. This column shows which company owns the block your computer connected to — often a hosting or cloud provider rather than the brand you recognise, because most services rent their infrastructure."},
	"signed": {Term: "Signed", Short: "The publisher's identity is verified.",
		Long: "Reputable software carries a digital signature naming the company that made it, which Windows checks. It proves who published the program, not that the program is safe — but unsigned software from an unusual place is worth more attention."},
	"process": {Term: "Process", Short: "A program that is currently running.",
		Long: "A program while it is running. Opening one app can start several processes — a browser typically runs one per tab — which is why the same name can appear many times."},
	"loopback": {Term: "Local address", Short: "Your own computer, or your home network.",
		Long: "Addresses that never leave your house: your own computer, your router, your printer, other devices on your wi-fi. Nothing here is phoning home to anyone, which is why these are hidden unless you ask for them."},
	"beacon": {Term: "Checking in on a timer", Short: "Connecting at a fixed, regular interval.",
		Long: "Some programs connect at perfectly regular intervals. Plenty of ordinary software does this to check for messages or updates. Remote-control malware also does it, to ask whoever installed it for instructions — so the question is whether you recognise the program, not the rhythm itself."},
	"quarantine": {Term: "Quarantine", Short: "Move a file somewhere it cannot run.",
		Long: "Moves the program file into a locked folder and takes away its permission to run, so it cannot start again. It is not deleted, and this can be undone."},
	"exfiltration": {Term: "Upload", Short: "Data leaving your computer.",
		Long: "Data going out from your computer to somewhere else. Normal all the time — sending an email, backing up photos. It matters when the amount is large, and it follows something reading files it had no business reading."},
}

// ForTerm returns a definition by key.
func ForTerm(key string) (Term, bool) {
	t, ok := terms[strings.ToLower(key)]
	return t, ok
}

// AllTerms returns every definition, for the glossary panel.
func AllTerms() map[string]Term { return terms }

// Count reports how many programs are described, for tests and diagnostics.
func Count() int { return len(programs) }
