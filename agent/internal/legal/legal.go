// Package legal holds the pre-release disclaimer the user must accept before
// the dashboard will do anything.
//
// The text lives here rather than in the HTML for three reasons: it is hashed
// so that changing the terms re-prompts everyone who accepted the old ones, the
// agent prints it to the log at startup whether or not anybody opens the
// dashboard, and one copy cannot drift from another.
//
// NOT LEGAL ADVICE. This was written in good faith to say plainly what the
// software does and does not promise. It has not been reviewed by a lawyer and
// must be before any production release.
package legal

import (
	"crypto/sha256"
	"encoding/hex"
)

// Headline is the one line shown in the title bar of the notice.
const Headline = "Read this before you trust it"

// Plain is the disclaimer as the user reads it: what it is, in the voice of
// somebody who would rather tell you than be sued by you.
//
// Written to be READ. Nobody reads a wall of capitals, which is precisely why
// so much of this genre is written in one — it discharges an obligation without
// transferring any understanding. The formal wording that a court would want to
// see is in Formal below, and the notice shows both.
const Plain = `I'll keep this short, because you have clicked through a hundred of these and read none of them.

**NiteWatch is not finished.** This is pre-release software, still being built. It has bugs I know about — they are listed in docs/known-limitations.md, and I would rather you read that than this — and bugs I do not, which are the interesting ones.

**It is not signed.** Windows will warn you about it. Windows is right to warn you: you are running an unsigned program that reads kernel telemetry and opens a network listener. You should find that suspicious. I would.

**There is no warranty. None.** Not a limited one, not one "to the extent permitted by law" with the good bits quietly removed. It is provided as-is. If it misses something, it missed it. If it cries wolf, it cried wolf. Nobody owes you a working product here.

**It is not antivirus, and it is not a replacement for any.** Leave Microsoft Defender switched on. NiteWatch watches and explains. It does not stand between you and anything — there is no kernel driver, so nothing is ever blocked before it happens.

**It can be wrong in both directions.** It will report things that are perfectly innocent, and it will stay silent about things that are not. Treat every alert as a prompt to look, never as a verdict.

**The buttons that change your machine are yours to press.** Stop a program, block an address, quarantine a file. They do exactly what they say, immediately, to the real thing. Read the sentence before you press the button.

**You use this at your own risk.** Yours. Not Threat Tape's, not mine. If that is not acceptable — and it is an entirely sensible thing to find unacceptable — close it now. No hard feelings.

**Questions, complaints, or a bug that made you swear?** threattape@gmail.com. I would genuinely rather hear it from you than not hear it at all. Tell me what it said and what your computer was actually doing.`

// Formal is the wording a court would expect, kept alongside the readable
// version rather than instead of it.
const Formal = `THE SOFTWARE IS PROVIDED "AS IS" AND "AS AVAILABLE", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.

THREAT TAPE LLC AND ITS CONTRIBUTORS DO NOT WARRANT THAT THE SOFTWARE WILL DETECT ANY PARTICULAR THREAT, THAT IT WILL OPERATE UNINTERRUPTED OR ERROR-FREE, THAT DEFECTS WILL BE CORRECTED, OR THAT ITS OUTPUT IS ACCURATE OR COMPLETE. THE SOFTWARE IS PRE-RELEASE AND IS NOT REPRESENTED AS FIT FOR PRODUCTION USE, FOR USE IN ANY ENVIRONMENT REQUIRING FAIL-SAFE PERFORMANCE, OR AS A SUBSTITUTE FOR ANTI-MALWARE SOFTWARE OR PROFESSIONAL SECURITY ADVICE.

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THREAT TAPE LLC OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES — INCLUDING LOSS OF DATA, LOSS OF PROFITS, BUSINESS INTERRUPTION, OR DAMAGE ARISING FROM UNDETECTED MALICIOUS ACTIVITY OR FROM ACTIONS TAKEN OR NOT TAKEN IN RELIANCE ON THE SOFTWARE'S OUTPUT — HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

YOU ASSUME ALL RISK ARISING FROM YOUR USE OF THE SOFTWARE, INCLUDING ALL RISK ARISING FROM REMEDIATION ACTIONS YOU CHOOSE TO PERFORM THROUGH IT. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OF IMPLIED WARRANTIES OR THE LIMITATION OF LIABILITY FOR INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO SOME OF THE ABOVE MAY NOT APPLY TO YOU.

Questions regarding these terms: threattape@gmail.com`

// Version identifies these exact terms. Acceptance is recorded against it, so
// editing the wording re-prompts everybody rather than silently relying on a
// consent given to different words.
func Version() string { return versionOf(Headline, Plain, Formal) }

// versionOf is separated so the hashing can be tested against varying input.
// Version() itself closes over constants, which makes "does it change when the
// text changes?" untestable through it.
func versionOf(headline, plain, formal string) string {
	sum := sha256.Sum256([]byte(headline + "\x00" + plain + "\x00" + formal))
	return hex.EncodeToString(sum[:8])
}

// LogText is the short form printed to the console at startup, so the terms are
// stated even when nobody opens the dashboard.
const LogText = `-------------------------------------------------------------------------
 NiteWatch is PRE-RELEASE software. No warranty of any kind. Not antivirus,
 and no substitute for it — leave Defender on. It can miss real problems and
 report harmless ones. Remediation buttons act immediately on real programs
 and files. You use it entirely at your own risk.
 Full text: open the dashboard, or read docs/known-limitations.md
 Questions: threattape@gmail.com
-------------------------------------------------------------------------`
