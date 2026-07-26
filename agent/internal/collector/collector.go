// Package collector is the orchestration loop: it pulls normalized events off a
// source, ingests them into the causal window, and records every outbound
// connection — enriched with the domain joined from DNS — into the ledger.
package collector

import (
	"context"
	"encoding/json"
	"log"
	"time"

	gr "github.com/ShaneDolphin/gorapide"

	"github.com/threattape/nitewatch/agent/internal/autostart"
	"github.com/threattape/nitewatch/agent/internal/detect"
	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/filewatch"
	"github.com/threattape/nitewatch/agent/internal/graph"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/notify"
	"github.com/threattape/nitewatch/agent/internal/recon"
	"github.com/threattape/nitewatch/agent/internal/resolve"
	"github.com/threattape/nitewatch/agent/internal/settings"
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
	// SignerLookup reports whether an executable is signed and by whom.
	// Injected like ImageLookup so the collector stays platform-agnostic.
	SignerLookup func(path string) (signed bool, signer string)
	// ImageLookup resolves a PID to an image path for processes the graph never
	// saw start (i.e. everything already running when the agent launched).
	// Injected so the collector stays platform-agnostic and testable.
	ImageLookup func(pid uint32) string
	// Detect, if set, evaluates rules against each recorded connection.
	Detect *detect.Engine
	// Notify delivers user-visible notifications for high-severity alerts.
	Notify *notify.Gate
	// Live, if set, supersedes the static fields above: it is read on every
	// connection so dashboard edits take effect without a restart (restarting
	// would discard the live causal window).
	Live *settings.Store
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
	suppress   *detect.Suppressor
	files      *filewatch.Tracker

	// per-ingest scratch, set before detection runs
	lastID       gr.EventID
	firstContact bool
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
		suppress:   detect.NewSuppressor(),
		files:      filewatch.NewTracker(),
	}
}

// Suppressor exposes the noise-control gates so the API can record user
// "always allow" decisions against the same instance the collector consults.
func (c *Collector) Suppressor() *detect.Suppressor { return c.suppress }

// LoadAllows restores persisted allow decisions at startup.
func (c *Collector) LoadAllows() {
	keys, err := c.ledger.Allows()
	if err != nil {
		return
	}
	c.suppress.AddKeys(keys)
}

// Run consumes the source until its channel closes or ctx is cancelled.
func (c *Collector) Run(ctx context.Context) error {
	ch, err := c.src.Events(ctx)
	if err != nil {
		return err
	}
	go c.backfillNames(ctx)
	if c.opts.Detect != nil {
		go c.watchAutostart(ctx)
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

	switch e.Kind {
	case event.KindProcStart:
		// Backup-destruction tools are judged the moment they start: by the
		// time they finish, the restore points are already gone.
		if c.opts.Detect != nil && filewatch.ShadowCopyTool(e.Image) {
			c.reportFile(detect.FileSubject{
				PID: e.PID, Image: e.Image, ToolRun: shortBase(e.Image),
			}, e.Time)
		}
	case event.KindProcExit:
		c.files.Forget(e.PID)
	case event.KindFileWrite:
		if c.opts.Detect != nil {
			c.onFileWrite(e)
		}
		return
	}

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
	cfg := c.config()
	if !cfg.IncludeLocal && !c.localNets.IsExternal(peerIP) {
		return // loopback / LAN / link-local: not a phone-home, just noise
	}
	// Prefer the passively-observed name: it's what the program actually asked
	// for. Fall back to reverse DNS only when there's no answer.
	domain := c.window.Current().DomainFor(id)
	if domain == "" && cfg.ResolveNames {
		domain = c.resolver.Lookup(peerIP)
	}

	c.lastID = id
	c.firstContact = c.ledger.IsNewDestination(imageFor(e, c), domainOrIP(domain, peerIP))

	var info recon.Info
	if c.opts.Recon != nil && cfg.Recon {
		info = c.opts.Recon.Lookup(peerIP)
	}

	// Serialize the causal chain now: the live poset window is bounded, so the
	// explanation must be captured while the ancestors still exist.
	story := ""
	if st := c.window.Current().StoryFor(id); len(st.Steps) > 0 {
		if b, err := json.Marshal(st); err == nil {
			story = string(b)
		}
	}

	image := e.Image
	if image == "" {
		image = c.window.Current().ImageFor(e.PID)
	}
	if image == "" {
		image = c.lookupImage(e.PID)
	}

	conn := ledger.Connection{
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
		Story:      story,
	}
	_ = c.ledger.RecordConnectionDedup(conn, c.dedupWindow())

	if c.opts.Detect != nil {
		c.runDetections(e, conn, info, domain)
	}
}

// runDetections evaluates rules against a just-recorded connection and persists
// any alerts. Detection never blocks or fails ingestion: a rule engine problem
// must not cost us the flight recorder.
func (c *Collector) runDetections(e event.NormalizedEvent, conn ledger.Connection, info recon.Info, domain string) {
	// The connection row is the alert's anchor, so resolve its id first.
	id, err := c.ledger.ConnectionID(conn.PID, conn.RemoteIP, conn.RemotePort, conn.Proto)
	if err != nil || id == 0 {
		return
	}
	subject := detect.Subject{
		Event:        e,
		Conn:         conn,
		Recon:        info,
		Domain:       domain,
		HadDNS:       c.window.Current().DomainFor(c.lastID) != "",
		FirstContact: c.firstContact,
	}
	c.suppress.Observe(conn.Image, e.Time)
	for _, d := range c.opts.Detect.Evaluate(subject) {
		if v := c.suppress.Check(d, subject, e.Time); v.Suppressed {
			continue
		}
		created, err := c.ledger.RecordAlert(ledger.Alert{
			Time:      e.Time,
			RuleID:    d.Rule.ID,
			Area:      string(d.Rule.Area),
			Severity:  string(d.Rule.Severity),
			Title:     d.Rule.RenderTitle(d.Fields),
			Narrative: d.Rule.RenderNarrative(d.Fields),
			Playbook:  d.Rule.RenderPlaybook(d.Fields),
			ConnID:    id,
			Evidence:  d.Fields,
		})
		if err == nil && created {
			log.Printf("ALERT [%s] %s", d.Rule.Severity, d.Rule.RenderTitle(d.Fields))
		}
	}
}

// imageFor resolves the acting image the same way the ledger row does.
func imageFor(e event.NormalizedEvent, c *Collector) string {
	if e.Image != "" {
		return e.Image
	}
	if img := c.window.Current().ImageFor(e.PID); img != "" {
		return img
	}
	return c.lookupImage(e.PID)
}

func domainOrIP(domain, ip string) string {
	if domain != "" {
		return domain
	}
	return ip
}

// config returns the effective settings, preferring the live store.
func (c *Collector) config() settings.Values {
	if c.opts.Live != nil {
		return c.opts.Live.Get()
	}
	return settings.Values{
		IncludeLocal: c.opts.IncludeLocal,
		ResolveNames: c.opts.ResolveNames,
		Recon:        c.opts.Recon != nil,
	}
}

func (c *Collector) dedupWindow() time.Duration {
	if c.opts.Live != nil {
		return c.opts.Live.DedupWindow()
	}
	return c.opts.DedupWindow
}

// onFileWrite feeds file activity to the burst tracker and the credential
// detector.
func (c *Collector) onFileWrite(e event.NormalizedEvent) {
	image := e.Image
	if image == "" {
		image = c.window.Current().ImageFor(e.PID)
	}
	if image == "" {
		image = c.lookupImage(e.PID)
	}

	switch filewatch.Classify(e.Path) {
	case filewatch.Credential:
		// Reading a secret store is judged on the spot: one read is the whole
		// event, and waiting for a pattern would mean waiting until after the
		// passwords were already taken.
		signed, signer := c.signerOf(image)
		c.reportFile(detect.FileSubject{
			PID: e.PID, Image: image, Path: e.Path, Signed: signed, Signer: signer,
		}, e.Time)
	case filewatch.UserDocument, filewatch.RansomNote:
		burst := c.files.Record(e.PID, image, e.Path, e.Time)
		if filewatch.Assess(burst) == filewatch.Nothing {
			return
		}
		signed, signer := c.signerOf(image)
		c.reportFile(detect.FileSubject{
			PID: e.PID, Image: image, Signed: signed, Signer: signer, Burst: burst,
		}, e.Time)
	}
}

func (c *Collector) signerOf(image string) (bool, string) {
	if c.opts.SignerLookup == nil || image == "" {
		return false, ""
	}
	return c.opts.SignerLookup(image)
}

func shortBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// reportFile persists and notifies file-activity detections.
func (c *Collector) reportFile(subj detect.FileSubject, at time.Time) {
	for _, d := range c.opts.Detect.EvaluateFile(subj) {
		// File alerts anchor on the process rather than a connection, so one
		// encryption sweep produces one alert instead of one per file.
		anchor := -int64(subj.PID) - 1
		created, err := c.ledger.RecordAlert(ledger.Alert{
			Time: at, RuleID: d.Rule.ID, Area: string(d.Rule.Area),
			Severity:  string(d.Rule.Severity),
			Title:     d.Rule.RenderTitle(d.Fields),
			Narrative: d.Rule.RenderNarrative(d.Fields),
			Playbook:  d.Rule.RenderPlaybook(d.Fields),
			ConnID:    anchor,
			Evidence:  d.Fields,
		})
		if err == nil && created {
			title := d.Rule.RenderTitle(d.Fields)
			log.Printf("ALERT [%s] %s", d.Rule.Severity, title)
			c.opts.Notify.Deliver(d.Rule.ID, notify.Alert{
				Severity: string(d.Rule.Severity), Title: title,
				Body: d.Rule.RenderNarrative(d.Fields),
			}, at)
		}
	}
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
			if !c.config().ResolveNames {
				continue
			}
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

// watchAutostart polls the places software registers itself to run at startup
// and alerts on what appears.
//
// The FIRST scan establishes a baseline and deliberately raises nothing. A new
// install would otherwise greet the user with an alert for every program
// already on their PC — the fastest possible way to teach someone that this
// tool is noise. Only changes after that point are events.
func (c *Collector) watchAutostart(ctx context.Context) {
	baseline, err := autostart.Scan()
	if err != nil {
		return
	}
	log.Printf("autostart: baseline established (%d entries)", len(baseline.Entries))
	prev := baseline

	t := time.NewTicker(autostartInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur, err := autostart.Scan()
			if err != nil {
				continue
			}
			for _, ch := range autostart.Diff(prev, cur) {
				c.reportAutostart(ch)
			}
			prev = cur
		}
	}
}

// autostartInterval balances catching a change promptly against reading the
// registry constantly. Persistence is about surviving reboots, so a change is
// still worth reporting a minute later.
const autostartInterval = 30 * time.Second

func (c *Collector) reportAutostart(ch autostart.Change) {
	target := autostart.TargetPath(ch.Entry.Target)
	subj := detect.PersistSubject{Change: ch}
	if c.opts.SignerLookup != nil && target != "" {
		subj.Signed, subj.Signer = c.opts.SignerLookup(target)
	}

	for _, d := range c.opts.Detect.EvaluatePersistence(subj) {
		// Persistence alerts anchor to no connection, so they dedupe on the
		// entry itself: re-detecting the same autostart must not re-alert.
		created, err := c.ledger.RecordAlert(ledger.Alert{
			Time:      time.Now(),
			RuleID:    d.Rule.ID,
			Area:      string(d.Rule.Area),
			Severity:  string(d.Rule.Severity),
			Title:     d.Rule.RenderTitle(d.Fields),
			Narrative: d.Rule.RenderNarrative(d.Fields),
			Playbook:  d.Rule.RenderPlaybook(d.Fields),
			ConnID:    -autostartAnchor(ch),
			Evidence:  d.Fields,
		})
		if err == nil && created {
			title := d.Rule.RenderTitle(d.Fields)
			log.Printf("ALERT [%s] %s", d.Rule.Severity, title)
			c.opts.Notify.Deliver(d.Rule.ID, notify.Alert{
				Severity: string(d.Rule.Severity), Title: title,
				Body: d.Rule.RenderNarrative(d.Fields),
			}, time.Now())
		}
	}
}

// autostartAnchor derives a stable negative pseudo-connection id from an entry,
// so the (rule_id, conn_id) uniqueness index dedupes persistence alerts too.
// Negative values cannot collide with real connection ids.
func autostartAnchor(ch autostart.Change) int64 {
	var h int64 = 1469598103934665603
	for _, b := range []byte(ch.Entry.ID() + "|" + ch.Entry.Target) {
		h ^= int64(b)
		h *= 1099511628211
	}
	if h < 0 {
		h = -h
	}
	return h%1000000000 + 1
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
