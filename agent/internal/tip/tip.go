// Package tip holds the shareware-style contribution notice.
//
// The text lives here rather than in the HTML for the same reasons the
// disclaimer does: one copy that cannot drift, and reachable from the agent
// without a browser.
//
// On the honor system, which is a design decision and not laziness. Checking
// whether somebody actually contributed would mean this program contacting a
// server of mine to ask — a phone-home, on a schedule, keyed to an identifier
// that distinguishes one installation from another. NiteWatch's entire pitch is
// that it does not do that. Building a licence check would trade the product's
// central promise for five dollars a month, so the box is a box, and ticking it
// is taken at face value.
package tip

// PayPal is where a contribution goes. Opened only when the user clicks it.
const PayPal = "https://paypal.me/threattape"

// Contact is where somebody sends the name they want in the credits.
const Contact = "threattape@gmail.com"

// CreditsThreshold is the contribution at which a name goes in the credits.
const CreditsThreshold = "$25"

// MonthlyThreshold is the recurring amount that stops this notice appearing.
const MonthlyThreshold = "$5"

// Headline is the title of the notice.
const Headline = "Shareware. Remember shareware?"

// Body is the ask, in the voice of somebody who would rather be honest than
// effective. Deliberately free of the usual machinery — no countdown before the
// dismiss button works, no "maybe later" phrased to make you feel cheap, no
// second nag on the way out. Those tricks work, which is exactly the problem
// with them: a security tool asking you to trust its judgement cannot also be
// caught manipulating you over five dollars.
const Body = `This is the part where I ask you for money. I will be quick, and I will be honest about it.

**NiteWatch is free. The whole thing.** Not a trial. Not a crippled build with the useful detections behind a paywall. Not free for thirty days and then properly obnoxious. Every feature works the same whether you pay or not, and nothing in here expires or degrades. If you never give me a cent, it keeps doing its job and I am genuinely fine with that.

**I would still appreciate a few dollars.** I wrote this because consumer security software mostly tells you a threat was "quarantined" and leaves you no wiser about your own computer. Building the alternative takes time I could bill somebody for.

**Contribute ` + MonthlyThreshold + ` a month or more and this window stops appearing.** It runs on the honor system: tick the box below and I will believe you. I have no way to check, and I am not going to build one — checking would mean this program calling home to a server of mine to ask whether you are paid up, on a schedule, keyed to something that identifies your machine. I have spent this entire project promising you it does not phone anybody. I am not breaking that for five dollars a month.

**Contribute ` + CreditsThreshold + ` or more and you go in the credits,** if you want to be. Email ` + Contact + ` with the name you would like on it — a real name, a handle, your dog, I do not mind.

**If money is tight, close this and do not think about it again.** Working security software should not be a thing you have to afford. The most useful thing you can send me costs nothing anyway: when NiteWatch gets something wrong — screams about a program that was minding its own business, or sits silent through something it should have caught — tell me. That is worth more to me than the five dollars, and I mean that literally.`

// Dismissed is shown after somebody says they contribute — brief, and without
// a receipt, since there is nothing to receipt.
const Dismissed = `Noted, and thank you. This window will not come back.

If you want the credits, email ` + Contact + ` with the name to use.`

// LogText is printed to the console at startup, so the ask exists for somebody
// running the agent headless who never opens the dashboard.
const LogText = ` NiteWatch is free and always will be. If it earns its keep, ` + PayPal
