package source

import (
	"net"
	"strings"
)

// parseDNSAnswers extracts IP literals from the Windows DNS-Client QueryResults
// field. The format is a ';'-separated list whose entries may be bare addresses
// ("93.184.216.34"), CNAME targets, or "type: N value" tuples. IPv4-mapped IPv6
// results ("::ffff:93.184.216.34") are normalized to their IPv4 form so they
// join against the address the Kernel-Network provider reports.
//
// This lives in a build-tag-free file so it is unit-testable off Windows.
func parseDNSAnswers(raw string) []string {
	var out []string
	for _, tok := range strings.Split(raw, ";") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// Strip a leading "type: N " tuple prefix if present.
		if i := strings.LastIndex(tok, " "); i >= 0 && strings.HasPrefix(strings.ToLower(tok), "type") {
			tok = strings.TrimSpace(tok[i+1:])
		}
		if ip := normalizeIP(tok); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// normalizeIP returns a canonical string form of an IP literal, or "" if the
// token is not an address. IPv4-mapped IPv6 collapses to plain IPv4.
func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// FormatHostPort renders an address:port pair, bracketing IPv6 so the result is
// unambiguous ("[2600:1700::1]:443" rather than "2600:1700::1:443").
func FormatHostPort(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + itoa(int(port))
	}
	return ip + ":" + itoa(int(port))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
