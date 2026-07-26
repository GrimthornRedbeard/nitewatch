package intel

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DefaultSources are the public feeds NiteWatch matches against.
//
// LICENSING IS A SHIPPING CONSTRAINT HERE, NOT A FOOTNOTE. This product is
// commercial and closed-source, and it caches feed data on customer machines —
// which is redistribution, not merely use. Only sources whose terms clearly
// permit that appear below. See docs/feed-licensing.md for the full analysis
// and the per-source evidence.
//
// Removed 2026-07-26 after review: abuse.ch ThreatFox and URLhaus. Both
// carried CC0 grants explicitly permitting commercial use; abuse.ch REMOVED
// those grants (URLhaus 2024-12, ThreatFox 2025-03) and its umbrella Terms of
// Use now route commercial users to a paid Spamhaus subscription. The legacy
// unauthenticated export endpoints still respond, but a working URL is not a
// licence. Do not re-add them without a written agreement.
var DefaultSources = []Source{
	{
		// CC0, stated on the blocklist page: usable commercially "without any
		// limitations". Note the feed has been stale since 2026-03 and its
		// recommended list is near-empty — kept because the grant is clean, not
		// because it is currently productive.
		Name: "feodo", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
		Kind: KindIP, Confidence: Malicious,
		Reason: "listed by abuse.ch Feodo Tracker as botnet command-and-control infrastructure",
	},
	{
		// BSD 3-Clause (Emerging Threats Open). Commercial use permitted with
		// the copyright notice reproduced — see NOTICE. This is the botnet
		// command-and-control destination set: the RIGHT data for watching
		// outbound connections, unlike attack-source feeds which list inbound
		// scanners a home router already drops.
		Name: "et-botcc", URL: "https://rules.emergingthreats.net/blockrules/emerging-botcc.rules",
		Kind: KindSuricataRule, Confidence: Malicious,
		Reason: "listed by Emerging Threats as botnet command-and-control infrastructure",
	},
	{
		// CC0 via the Tor Project. Served from CollecTor, which sits under the
		// site carrying the CC0 declaration; check.torproject.org publishes no
		// licence of its own.
		Name: "tor-exits", URL: "https://collector.torproject.org/recent/exit-lists/",
		Kind: KindTorExitList, Confidence: Context,
		Reason: "a Tor exit node — normal for some software, notable for others",
	},
}

// RefreshAfter is how stale cached feeds may get. C2 infrastructure rotates
// fast, so this is much shorter than the recon dataset's weekly refresh.
const RefreshAfter = 6 * time.Hour

// EnsureLoaded loads cached feeds, downloading any that are missing or stale.
// Best-effort per feed: one unreachable source must not blind the others.
func (s *Store) EnsureLoaded(ctx context.Context, cacheDir string, sources []Source) error {
	var loaded int
	var firstErr error
	for _, src := range sources {
		path := filepath.Join(cacheDir, src.Name+".txt")
		if !fresh(path) {
			if err := download(ctx, src.URL, path); err != nil {
				log.Printf("intel: %s refresh failed (%v); using cache if present", src.Name, err)
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		f, err := os.Open(path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		err = s.LoadList(f, src)
		f.Close()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		loaded++
	}
	if loaded == 0 {
		if firstErr != nil {
			return fmt.Errorf("no threat feeds available: %w", firstErr)
		}
		return fmt.Errorf("no threat feeds available")
	}
	ips, domains := s.Count()
	log.Printf("intel: %d/%d feeds loaded (%d addresses, %d domains)", loaded, len(sources), ips, domains)
	return nil
}

// RefreshLoop keeps feeds current for a long-running agent.
func (s *Store) RefreshLoop(ctx context.Context, cacheDir string, sources []Source) {
	t := time.NewTicker(RefreshAfter)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.EnsureLoaded(ctx, cacheDir, sources); err != nil {
				log.Printf("intel: refresh failed: %v", err)
			}
		}
	}
}

func fresh(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Size() > 0 && time.Since(fi.ModTime()) < RefreshAfter
}

func download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NiteWatch/0.1 (+local endpoint agent)")
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".feed-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
