// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

package recon

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DatasetURL is the public ip2asn combined (IPv4+IPv6) table. Fetching it is
// the ONLY network access this package makes: a whole-file download, identical
// for every user, revealing nothing about what this machine talks to.
const DatasetURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

// RefreshAfter is how stale a cached dataset may get before re-downloading.
// Address allocations move slowly; weekly is plenty.
const RefreshAfter = 7 * 24 * time.Hour

// EnsureLoaded loads the cached dataset, downloading it first if absent or
// stale. It is best-effort: on any failure the DB simply stays empty and
// lookups return nothing, because recon is enrichment, not a hard dependency.
func (d *DB) EnsureLoaded(ctx context.Context, cachePath string) error {
	if fresh(cachePath) {
		if err := d.loadFile(cachePath); err == nil {
			return nil
		}
		// A corrupt cache should not be fatal — fall through and re-download.
	}
	if err := download(ctx, DatasetURL, cachePath); err != nil {
		// Stale data beats none: try whatever is on disk.
		if loadErr := d.loadFile(cachePath); loadErr == nil {
			return fmt.Errorf("refresh failed, using cached dataset: %w", err)
		}
		return err
	}
	return d.loadFile(cachePath)
}

// RefreshLoop keeps the dataset current for long-running agents.
func (d *DB) RefreshLoop(ctx context.Context, cachePath string) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if fresh(cachePath) {
				continue
			}
			if err := d.EnsureLoaded(ctx, cachePath); err != nil {
				log.Printf("recon: dataset refresh failed: %v", err)
			}
		}
	}
}

func fresh(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Size() > 0 && time.Since(fi.ModTime()) < RefreshAfter
}

func (d *DB) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return d.Load(f)
}

// download fetches and decompresses the dataset, writing via a temp file so an
// interrupted download can never leave a half-written cache in place.
func download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dataset download: HTTP %s", resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".ip2asn-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		tmp.Close()
		return err
	}
	defer gz.Close()

	if _, err := io.Copy(tmp, gz); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dest)
}
