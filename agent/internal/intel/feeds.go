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
// Tor exits are deliberately Context, not Malicious: using Tor is legitimate,
// and auto-flagging it would both slander normal users and train people to
// ignore alerts. It contributes to a verdict, never causes one alone.
var DefaultSources = []Source{
	{
		Name: "feodo", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		Kind: KindIP, Confidence: Malicious,
		Reason: "listed by abuse.ch Feodo Tracker as botnet command-and-control infrastructure",
	},
	{
		Name: "threatfox", URL: "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
		Kind: KindIP, Confidence: Malicious,
		Reason: "listed by abuse.ch ThreatFox as a malware command-and-control address",
	},
	{
		Name: "urlhaus", URL: "https://urlhaus.abuse.ch/downloads/text/",
		Kind: KindDomain, Confidence: Malicious,
		Reason: "listed by abuse.ch URLhaus as distributing malware",
	},
	{
		Name: "tor-exits", URL: "https://check.torproject.org/torbulkexitlist",
		Kind: KindIP, Confidence: Context,
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
