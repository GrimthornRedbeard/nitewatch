// Package intel matches destinations against public threat-intelligence feeds,
// entirely offline.
//
// Same privacy rule as the rest of the agent: feeds are pulled DOWN in full and
// matched locally. Nothing about which addresses this machine contacts is ever
// sent anywhere — an agent that phoned home about your traffic to check whether
// your traffic phones home would be self-defeating.
package intel

import (
	"bufio"
	"io"
	"strings"
	"sync"
)

// Confidence says how a feed hit should be treated.
type Confidence string

const (
	// Malicious feeds list infrastructure with a specific abuse report.
	Malicious Confidence = "malicious"
	// Context feeds are informative, not damning — Tor exits, for instance:
	// legitimate for some users, notable for others. Never auto-flag alone.
	Context Confidence = "context"
)

// Match describes why a destination was flagged.
type Match struct {
	Feed       string     `json:"feed"`
	Reason     string     `json:"reason"`
	Confidence Confidence `json:"confidence"`
}

// Source describes one downloadable feed.
type Source struct {
	Name       string
	URL        string
	Kind       Kind
	Confidence Confidence
	Reason     string
}

// Kind is what the feed's entries are.
type Kind int

const (
	KindIP Kind = iota
	KindDomain
)

// Store holds the loaded feed data.
type Store struct {
	mu      sync.RWMutex
	ips     map[string]Match
	domains map[string]Match
}

func New() *Store {
	return &Store{ips: map[string]Match{}, domains: map[string]Match{}}
}

// Loaded reports whether any entries are present.
func (s *Store) Loaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ips)+len(s.domains) > 0
}

// Count returns the number of loaded IP and domain entries.
func (s *Store) Count() (ips, domains int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ips), len(s.domains)
}

// LoadList reads a feed. abuse.ch lists are plain text or CSV with '#' comments;
// the first comma-separated field is the indicator. An "ip:port" entry (Feodo
// style) contributes its address.
func (s *Store) LoadList(r io.Reader, src Source) error {
	entries := map[string]Match{}
	m := Match{Feed: src.Name, Reason: src.Reason, Confidence: src.Confidence}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		field := line
		if i := strings.IndexAny(field, ",\t"); i >= 0 {
			field = strings.TrimSpace(field[:i])
		}
		field = strings.Trim(field, `"`)
		if field == "" {
			continue
		}
		switch src.Kind {
		case KindIP:
			// Feodo-style "1.2.3.4:443" -> the address. Leave IPv6 alone: it
			// contains colons legitimately and these feeds are v4 in practice.
			if i := strings.LastIndex(field, ":"); i >= 0 && strings.Count(field, ":") == 1 {
				field = field[:i]
			}
		case KindDomain:
			field = strings.ToLower(strings.TrimSuffix(field, "."))
			// URLhaus ships full URLs; reduce to the host.
			if i := strings.Index(field, "://"); i >= 0 {
				field = field[i+3:]
			}
			if i := strings.IndexAny(field, "/:"); i >= 0 {
				field = field[:i]
			}
		}
		if field != "" {
			entries[field] = m
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	dst := s.ips
	if src.Kind == KindDomain {
		dst = s.domains
	}
	for k, v := range entries {
		dst[k] = v
	}
	return nil
}

// FlagIP reports whether an address appears on a loaded feed.
func (s *Store) FlagIP(ip string) (Match, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.ips[ip]
	return m, ok
}

// FlagDomain reports whether a hostname appears on a loaded feed. Parent domains
// are checked too, so a feed entry for "evil.test" also flags "cdn.evil.test".
func (s *Store) FlagDomain(host string) (Match, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return Match{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for {
		if m, ok := s.domains[host]; ok {
			return m, true
		}
		i := strings.Index(host, ".")
		if i < 0 {
			return Match{}, false
		}
		host = host[i+1:]
		if !strings.Contains(host, ".") {
			// Never match a bare TLD: an entry for "com" must not flag everything.
			return Match{}, false
		}
	}
}
