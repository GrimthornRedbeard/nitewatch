// Package collector is the orchestration loop: it pulls normalized events off a
// source, ingests them into the causal window, and records every outbound
// connection — enriched with the domain joined from DNS — into the ledger.
package collector

import (
	"context"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/graph"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/resolve"
	"github.com/threattape/nitewatch/agent/internal/source"
)

// Options tunes what the collector records.
type Options struct {
	// IncludeLocal records loopback/private/link-local destinations too. Off by
	// default: on a normal desktop that traffic is the overwhelming majority of
	// connection events and none of it is "phoning home".
	IncludeLocal bool
	// ResolveNames enables reverse-DNS fallback for destinations the passive DNS
	// join didn't name.
	ResolveNames bool
	// ImageLookup resolves a PID to an image path for processes the graph never
	// saw start (i.e. everything already running when the agent launched).
	// Injected so the collector stays platform-agnostic and testable.
	ImageLookup func(pid uint32) string
}

type Collector struct {
	src      source.EventSource
	window   *graph.Window
	ledger   *ledger.DB
	resolver *resolve.Resolver
	opts     Options

	imageCache map[uint32]string
}

// New builds a collector with default options (skip local traffic, resolve names).
func New(src source.EventSource, led *ledger.DB) *Collector {
	return NewWithOptions(src, led, Options{ResolveNames: true})
}

// NewWithOptions builds a collector over a source and ledger.
func NewWithOptions(src source.EventSource, led *ledger.DB, opts Options) *Collector {
	return &Collector{
		src:        src,
		window:     graph.NewWindow(graph.WindowConfig{}),
		ledger:     led,
		resolver:   resolve.New(),
		opts:       opts,
		imageCache: make(map[uint32]string),
	}
}

// Run consumes the source until its channel closes or ctx is cancelled.
func (c *Collector) Run(ctx context.Context) error {
	ch, err := c.src.Events(ctx)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-ch:
			if !ok {
				return nil
			}
			c.ingest(e)
		}
	}
}

func (c *Collector) ingest(e event.NormalizedEvent) {
	id := c.window.Ingest(e)
	if e.Kind != event.KindNetConnect {
		return
	}
	if !c.opts.IncludeLocal && !resolve.IsPublic(e.RemoteIP) {
		return // loopback/private/link-local: not a phone-home, just noise
	}

	// Prefer the passively-observed name: it's what the program actually asked
	// for. Fall back to reverse DNS only when there's no answer.
	domain := c.window.Current().DomainFor(id)
	if domain == "" && c.opts.ResolveNames {
		domain = c.resolver.Lookup(e.RemoteIP)
	}

	image := e.Image
	if image == "" {
		image = c.window.Current().ImageFor(e.PID)
	}
	if image == "" {
		image = c.lookupImage(e.PID)
	}

	_ = c.ledger.RecordConnection(ledger.Connection{
		Time:       e.Time,
		PID:        e.PID,
		Image:      image,
		RemoteIP:   e.RemoteIP,
		RemotePort: e.RemotePort,
		Proto:      e.Proto,
		Domain:     domain,
	})
}

// lookupImage resolves and caches a PID's image path via the injected lookup.
// PIDs are reused by the OS, but within a collector run the cache is bounded by
// the process table and stale entries only affect display of exited processes.
func (c *Collector) lookupImage(pid uint32) string {
	if c.opts.ImageLookup == nil || pid == 0 {
		return ""
	}
	if img, ok := c.imageCache[pid]; ok {
		return img
	}
	img := c.opts.ImageLookup(pid)
	c.imageCache[pid] = img
	return img
}
