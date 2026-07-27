package graph

import (
	"fmt"
	"strings"
)

// Peer is what the connection reached, supplied by the caller because the
// poset knows addresses but not who owns them.
type Peer struct {
	IP        string
	Port      uint16
	Domain    string
	Owner     string
	Country   string
	BytesSent uint64
	BytesRecv uint64
}

// Narrate turns a causal chain into a paragraph a person can read.
//
// The step list is accurate and nearly useless to a non-analyst: it asks the
// reader to assemble the meaning themselves. The same facts as a sentence —
// "you started Brave, which looked up the address, connected to a server
// operated by Anthropic, and read 12 files in your Pictures folder" — is the
// difference between evidence and an explanation.
//
// Every clause is grounded in an observed event. Where the graph cannot support
// a claim, the sentence does not make it: a program whose parent we never saw
// is "was running" rather than "you started", because guessing at the user's
// involvement is precisely the kind of confident wrongness that makes people
// stop believing a security tool.
func Narrate(story Story, ctx Context, peer Peer) string {
	subject := programName(story, ctx)

	// Sentence one: how the program came to be running.
	var opening string
	switch {
	case ctx.UserLaunched && ctx.LaunchedBy != "":
		opening = fmt.Sprintf("You started %s from %s", subject, ctx.LaunchedBy)
	case ctx.LaunchedBy != "":
		opening = fmt.Sprintf("%s was started by %s", subject, ctx.LaunchedBy)
	default:
		// No parent observed: the process predates the agent, or its start was
		// missed. Say what we know rather than inventing a cause.
		opening = fmt.Sprintf("%s was already running", subject)
	}
	if len(ctx.Lineage) > 2 {
		opening += fmt.Sprintf(" (%s)", strings.Join(ctx.Lineage, " → "))
	}
	out := opening + "."

	// Sentence two: what it reached, and how much moved. Built as one clause so
	// it reads as a sentence rather than a list of facts joined by commas.
	var did []string
	if name := lookedUp(story); name != "" {
		did = append(did, "looked up "+name)
	}
	if dest := describePeer(peer); dest != "" {
		did = append(did, "connected to "+dest)
	}
	if len(did) > 0 {
		s := "It " + joinClauses(did)
		if v := describeVolume(peer); v != "" {
			s += ", " + v
		}
		out += " " + s + "."
	}

	// Sentence three: what else it touched, kept separate so the first two stay
	// readable.
	if extra := describeSideActivity(ctx); extra != "" {
		out += " " + extra
	}
	return out
}

// programName prefers the process the connection belongs to.
func programName(story Story, ctx Context) string {
	for i := len(story.Steps) - 1; i >= 0; i-- {
		if story.Steps[i].Source != "" {
			return story.Steps[i].Source
		}
	}
	if n := len(ctx.Lineage); n > 0 {
		return ctx.Lineage[n-1]
	}
	return "A program"
}

// lookedUp returns the name resolved on the way to this connection, if the
// chain contains one.
func lookedUp(story Story) string {
	for _, s := range story.Steps {
		if s.Kind == "DNSQuery" && s.Detail != "" {
			return s.Detail
		}
	}
	return ""
}

func describePeer(p Peer) string {
	if p.IP == "" && p.Domain == "" {
		return ""
	}
	var b strings.Builder
	if p.Domain != "" {
		b.WriteString(p.Domain)
		if p.IP != "" {
			fmt.Fprintf(&b, " (%s)", hostPort(p.IP, p.Port))
		}
	} else {
		b.WriteString(hostPort(p.IP, p.Port))
	}
	switch {
	case p.Owner != "" && p.Country != "":
		fmt.Fprintf(&b, " — a network operated by %s (%s)", p.Owner, p.Country)
	case p.Owner != "":
		fmt.Fprintf(&b, " — a network operated by %s", p.Owner)
	case p.Country != "":
		fmt.Fprintf(&b, " — registered in %s", p.Country)
	}
	return b.String()
}

func hostPort(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		if port != 0 {
			return fmt.Sprintf("[%s]:%d", ip, port)
		}
		return ip
	}
	if port != 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	return ip
}

func describeVolume(p Peer) string {
	switch {
	case p.BytesSent == 0 && p.BytesRecv == 0:
		return ""
	case p.BytesSent > 0 && p.BytesRecv > 0:
		return fmt.Sprintf("sending %s and receiving %s", human(p.BytesSent), human(p.BytesRecv))
	case p.BytesSent > 0:
		return fmt.Sprintf("sending %s", human(p.BytesSent))
	default:
		return fmt.Sprintf("receiving %s", human(p.BytesRecv))
	}
}

// describeSideActivity reports what the program did besides this connection —
// the files it touched and anywhere else it went.
func describeSideActivity(ctx Context) string {
	var files, others []string
	for _, a := range ctx.Recent {
		switch a.Kind {
		case "FileWrite":
			files = append(files, fmt.Sprintf("wrote %s in %s", countFiles(a.Count), shortFolder(a.Detail)))
		case "FileRead":
			files = append(files, fmt.Sprintf("read %s in %s", countFiles(a.Count), shortFolder(a.Detail)))
		case "RegPersist":
			others = append(others, "changed a startup setting")
		}
	}
	all := append(files, others...)
	if len(all) == 0 {
		return ""
	}
	if len(all) > 3 {
		all = all[:3]
	}
	return "Around the same time it " + joinClauses(all) + "."
}

// shortFolder trims a path to the part a person recognises: nobody reads
// "C:\\Users\\kevin\\Pictures\\holiday" as anything other than "Pictures\\holiday".
func shortFolder(p string) string {
	parts := strings.Split(strings.ReplaceAll(p, "/", `\`), `\`)
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, `\`)
}

func countFiles(n int) string {
	if n == 1 {
		return "1 file"
	}
	return fmt.Sprintf("%d files", n)
}

// joinClauses builds "a, b, and c" without a trailing comma before a lone item.
func joinClauses(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + ", " + parts[1]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
}

func human(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}
