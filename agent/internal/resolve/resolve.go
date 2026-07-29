// Copyright (C) 2026 Threat Tape LLC
// SPDX-License-Identifier: GPL-3.0-or-later

// Package resolve turns IP addresses into names when the passive DNS join
// can't. The causal DNS join (graph.DomainFor) is always preferred — it records
// the name the program actually asked for. This is the fallback: a cached
// reverse-DNS (PTR) lookup, which answers "who owns this address" for traffic
// that never had a visible lookup (IP literals, connections predating the
// agent, or resolutions the sensor missed).
package resolve

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// Resolver performs bounded, cached reverse-DNS lookups.
type Resolver struct {
	mu    sync.RWMutex
	cache map[string]string // IP -> name ("" = looked up, no name)

	timeout  time.Duration
	sem      chan struct{} // bounds concurrent in-flight lookups
	inFlight map[string]bool
}

func New() *Resolver {
	return &Resolver{
		cache:    make(map[string]string),
		timeout:  2 * time.Second,
		sem:      make(chan struct{}, 8),
		inFlight: make(map[string]bool),
	}
}

// Lookup returns a cached name for ip, or "" if unknown. It never blocks the
// caller: on a cache miss it kicks off a background lookup and returns "" now,
// so the next connection to the same address gets the name. Private, loopback,
// and link-local addresses are skipped — PTR lookups for those are pointless
// and would leak local topology to a resolver.
func (r *Resolver) Lookup(ip string) string {
	if ip == "" || !IsPublic(ip) {
		return ""
	}
	r.mu.RLock()
	name, ok := r.cache[ip]
	r.mu.RUnlock()
	if ok {
		return name
	}

	r.mu.Lock()
	if r.inFlight[ip] {
		r.mu.Unlock()
		return ""
	}
	r.inFlight[ip] = true
	r.mu.Unlock()

	go r.lookup(ip)
	return ""
}

func (r *Resolver) lookup(ip string) {
	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	var name string
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}

	r.mu.Lock()
	r.cache[ip] = name
	delete(r.inFlight, ip)
	r.mu.Unlock()
}

// IsPublic reports whether an address is routable on the internet — i.e. worth
// resolving and worth showing as an external destination. Loopback, private
// (RFC1918), link-local, CGNAT, and unique-local v6 all return false.
func IsPublic(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	// RFC 6598 carrier-grade NAT: 100.64.0.0/10
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return true
}
