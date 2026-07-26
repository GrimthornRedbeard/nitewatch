// Package collector is the orchestration loop: it pulls normalized events off a
// source, ingests them into the causal window, and records every outbound
// connection — enriched with the domain joined from DNS — into the ledger.
package collector

import (
	"context"
	"time"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/graph"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/recon"
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
	// Recon supplies offline address ownership (AS owner / country). Optional:
	// when nil, rows simply carry no ownership data.
	Recon *recon.DB
	// ImageLookup resolves a PID to an image path for processes the graph never
	// saw start (i.e. everything already running when the agent launched).
	// Injected so the collector stays platform-agnostic and testable.
	ImageLookup func(pid uint32) string
	// DedupWindow collapses repeated activity on the same flow into one ledger
	// row. The kernel reports network activity per packet, so without this a
	// single browser tab produces hundreds of identical rows. Zero disables it.
	DedupWindow time.Duration
}

// DefaultDedupWindow is the flow-collapsing window used unless overridden.
const DefaultDedupWindow = 5 * time.Minute

// DedupDisabled turns off flow collapsing (every event gets its own row).
const DedupDisabled = -1 * time.Nanosecond

type Collector struct {
	src       source.EventSource
	window    *graph.Window
	ledger    *ledger.DB
	resolver  *resolve.Resolver
	localNets *resolve.LocalNets
	opts      Options

	imageCache map[uint32]string
}

// New builds a collector with default options (skip local traffic, resolve names).
func New(src source.EventSource, led *ledger.DB) *Collector {
	return NewWithOptions(src, led, Options{ResolveNames: true})
}

// NewWithOptions builds a collector over a source and ledger. Defaults are
// applied here rather than in New so every caller gets them — a zero
// DedupWindow means "unset", not "disabled" (use DedupDisabled for that).
func NewWithOptions(src source.EventSource, led *ledger.DB, opts Options) *Collector {
	if opts.DedupWindow == 0 {
		opts.DedupWindow = DefaultDedupWindow
	} else if opts.DedupWindow == DedupDisabled {
		opts.DedupWindow = 0
	}
	return &Collector{
		src:        src,
		window:     graph.NewWindow(graph.WindowConfig{}),
		ledger:     led,
		resolver:   resolve.New(),
		localNets:  resolve.DetectLocalNets(),
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
	if c.opts.ResolveNames {
		go c.backfillNames(ctx)
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
	peerIP, peerPort, inbound := c.peer(e)
	if peerIP == "" {
		return
	}
	// "External" means routable AND not on one of our own attached networks.
	// The second half matters for IPv6, where LAN devices hold globally
	// routable addresses from the ISP-delegated prefix.
	if !c.opts.IncludeLocal && !c.localNets.IsExternal(peerIP) {
		return // loopback / LAN / link-local: not a phone-home, just noise
	}
	// Prefer the passively-observed name: it's what the program actually asked
	// for. Fall back to reverse DNS only when there's no answer.
	domain := c.window.Current().DomainFor(id)
	if domain == "" && c.opts.ResolveNames {
		domain = c.resolver.Lookup(peerIP)
	}

	var info recon.Info
	if c.opts.Recon != nil {
		info = c.opts.Recon.Lookup(peerIP)
	}

	image := e.Image
	if image == "" {
		image = c.window.Current().ImageFor(e.PID)
	}
	if image == "" {
		image = c.lookupImage(e.PID)
	}

	_ = c.ledger.RecordConnectionDedup(ledger.Connection{
		Time:       e.Time,
		PID:        e.PID,
		Image:      image,
		RemoteIP:   peerIP,
		RemotePort: peerPort,
		Proto:      e.Proto,
		Domain:     domain,
		Inbound:    inbound,
		ASN:        info.ASN,
		ASOrg:      info.Org,
		Country:    info.Country,
	}, c.opts.DedupWindow)
}

// backfillNames periodically attaches reverse-DNS names to rows that were
// written before their lookup completed. Without this, a short-lived flow whose
// packets all land before the resolver answers would stay nameless forever.
func (c *Collector) backfillNames(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ips, err := c.ledger.UnnamedIPs(200)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				// Lookup is async: this both consumes a completed answer and
				// primes the cache for the next pass.
				if name := c.resolver.Lookup(ip); name != "" {
					_ = c.ledger.SetDomainForIP(ip, name)
				}
			}
		}
	}
}

// peer determines which end of a network event is the remote party.
//
// The kernel reports addresses relative to the packet, so on a receive event
// the "destination" is this machine. Choosing blindly makes the agent record
// the user's own address as the peer it is talking to. The peer is whichever
// end is not one of our own addresses.
func (c *Collector) peer(e event.NormalizedEvent) (ip string, port uint16, inbound bool) {
	dstMine := e.RemoteIP != "" && c.localNets.IsLocal(e.RemoteIP)
	srcMine := e.SrcIP != "" && c.localNets.IsLocal(e.SrcIP)

	switch {
	case dstMine && !srcMine && e.SrcIP != "":
		// Traffic arriving at us: the source is the remote party.
		return e.SrcIP, e.SrcPort, true
	case e.RemoteIP != "":
		return e.RemoteIP, e.RemotePort, e.Inbound
	default:
		return e.SrcIP, e.SrcPort, true
	}
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
