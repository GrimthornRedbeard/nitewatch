// Command nitewatch is the NiteWatch flight-recorder agent.
//
// Run modes:
//
//	nitewatch                            live ETW + dashboard (Windows, elevated)
//	nitewatch --replay <file>            replay a .jsonl trace + dashboard (any OS)
//	nitewatch --no-serve --replay <file> replay to the ledger without the dashboard
//
// Double-clicking the exe on Windows runs the live+dashboard mode and opens the
// browser; if it is not elevated, the dashboard still comes up and shows a
// "Run as administrator" banner instead of exiting silently.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/threattape/nitewatch/agent/internal/api"
	"github.com/threattape/nitewatch/agent/internal/collector"
	"github.com/threattape/nitewatch/agent/internal/detect"
	"github.com/threattape/nitewatch/agent/internal/intel"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/legal"
	"github.com/threattape/nitewatch/agent/internal/notify"
	"github.com/threattape/nitewatch/agent/internal/platform"
	"github.com/threattape/nitewatch/agent/internal/rdap"
	"github.com/threattape/nitewatch/agent/internal/recon"
	"github.com/threattape/nitewatch/agent/internal/respond"
	"github.com/threattape/nitewatch/agent/internal/rules"
	"github.com/threattape/nitewatch/agent/internal/settings"
	"github.com/threattape/nitewatch/agent/internal/source"
	"github.com/threattape/nitewatch/agent/internal/tip"
	rulesdata "github.com/threattape/nitewatch/agent/rules"
)

var version = "0.1.0-dev"

// baseDir is the directory the agent keeps its files in — next to the exe, so
// there are no %ProgramData% permission variables to reason about during
// testing. Falls back to the working directory.
func baseDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

func main() {
	var (
		replayPath   = flag.String("replay", "", "replay events from a .jsonl trace instead of live ETW")
		serve        = flag.Bool("serve", true, "serve the localhost dashboard + API")
		open         = flag.Bool("open", true, "open the dashboard in a browser when serving (Windows)")
		dbPath       = flag.String("db", filepath.Join(baseDir(), "nitewatch.db"), "path to the connection ledger database")
		includeLocal = flag.Bool("include-local", false, "also record loopback/private/link-local destinations (noisy)")
		noResolve    = flag.Bool("no-resolve", false, "disable reverse-DNS lookup of destinations")
		noRecon      = flag.Bool("no-recon", false, "disable the offline IP-ownership dataset (no download)")
		noFeeds      = flag.Bool("no-feeds", false, "disable threat-intel feed downloads (rules still run)")
		rulesDir     = flag.String("rules", "", "load rule packs from this directory instead of the built-in set")
	)
	flag.Parse()

	closeLog := setupLogging()
	defer closeLog()

	// Any panic must leave a readable trail and hold the window open.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC: %v\n%s", r, debug.Stack())
			holdOpen()
			os.Exit(2)
		}
	}()

	log.Printf("NiteWatch agent %s", version)
	log.Print(legal.LogText)
	log.Print(tip.LogText)
	log.Printf("env: os=%s arch=%s elevated=%v", runtime.GOOS, runtime.GOARCH, platform.IsElevated())
	if exe, err := os.Executable(); err == nil {
		log.Printf("env: exe=%s", exe)
	}

	// Flags seed first-run defaults; the dashboard owns configuration after that.
	seed := settings.Defaults()
	seed.IncludeLocal = *includeLocal
	seed.ResolveNames = !*noResolve
	seed.Recon = !*noRecon

	opts := collector.Options{
		ImageLookup:  platform.ProcessImage,
		SignerLookup: platform.FileSigner,
		ProcessTable: func() ([]collector.ProcInfo, error) {
			ps, err := platform.ProcessTable()
			if err != nil {
				return nil, err
			}
			out := make([]collector.ProcInfo, 0, len(ps))
			for _, p := range ps {
				out = append(out, collector.ProcInfo{PID: p.PID, PPID: p.PPID, Image: p.Image, Services: p.Services})
			}
			return out, nil
		},
	}
	eng, feeds := startDetection(*rulesDir, *noFeeds)
	if eng != nil {
		opts.Detect = eng
	}
	if err := run(*replayPath, *serve, *open, *dbPath, opts, seed, eng, feeds); err != nil {
		log.Printf("fatal: %v", err)
		holdOpen()
		os.Exit(1)
	}
}

func run(replayPath string, serve, open bool, dbPath string, opts collector.Options, seed settings.Values,
	eng *detect.Engine, feeds *intel.Store) error {
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create ledger dir %q: %w", dir, err)
		}
	}
	log.Printf("ledger: opening %s", dbPath)
	led, err := ledger.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}
	defer led.Close()
	log.Printf("ledger: ready")

	cfg, err := settings.Open(led.SQL(), seed)
	if err != nil {
		return fmt.Errorf("open settings: %w", err)
	}
	opts.Live = cfg
	opts.Notify = notify.NewGate(notify.NewWindowsToast())
	if cfg.Get().Recon {
		opts.Recon = startRecon()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start the dashboard first so it is reachable even if the sensor can't start.
	var srv *api.Server
	if serve {
		quarantine := filepath.Join(baseDir(), "quarantine")
		srv = api.New(led).WithSettings(cfg).
			WithExecutor(respond.NewWindowsExecutor(quarantine), quarantine).
			// Registration lookups. Available, never automatic: nothing reaches
			// the registry unless the user presses the button for one address.
			WithLookups(rdap.New()).
			// The on-demand drill. Needs the live engine and feed store so the
			// test exercises the real rules rather than a copy of them.
			WithSelfTest(eng, feeds).
			WithShutdown(stop)
		if tok, err := api.NewToken(baseDir()); err == nil {
			srv = srv.WithToken(tok)
			log.Printf("api: token required; stored at %s", tok.Path())
		} else {
			log.Printf("api: could not create an auth token (%v); the local API is unauthenticated", err)
		}
		log.Printf("dashboard: http://%s", srv.Addr())
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				log.Printf("server stopped: %v", err)
			}
		}()
		if open && runtime.GOOS == "windows" {
			go func() {
				time.Sleep(600 * time.Millisecond) // let the listener bind
				_ = platform.OpenBrowser("http://" + srv.Addr())
			}()
		}
	}

	// Bring up telemetry. A failed live sensor is non-fatal WHILE serving — we
	// keep the dashboard up with an explanatory banner instead of exiting.
	src, srcErr := pickSource(replayPath)
	if srcErr != nil {
		if !serve {
			return srcErr
		}
		log.Printf("sensor unavailable: %v", srcErr)
		srv.SetStatus(api.Status{
			Source:   sourceName(replayPath),
			Running:  false,
			Elevated: platform.IsElevated(),
			Message:  srcErr.Error(),
		})
		log.Printf("dashboard is up; serving without live telemetry (Ctrl+C to stop)")
		<-ctx.Done()
		return nil
	}
	defer src.Close()

	if srv != nil {
		srv.SetStatus(api.Status{
			Source:   sourceName(replayPath),
			Running:  true,
			Elevated: platform.IsElevated(),
			Message:  "Telemetry flowing.",
		})
	}

	v := cfg.Get()
	log.Printf("settings: include-local=%v resolve-names=%v recon=%v dedup=%ds (editable in the dashboard)",
		v.IncludeLocal, v.ResolveNames, v.Recon, v.DedupSeconds)
	coll := collector.NewWithOptions(src, led, opts)
	coll.LoadAllows()
	if srv != nil {
		srv.WithSuppressor(coll.Suppressor())
	}
	collErr := make(chan error, 1)
	go func() { collErr <- coll.Run(ctx) }()

	if serve {
		log.Printf("running; dashboard at http://%s (Ctrl+C to stop)", srv.Addr())
		<-ctx.Done() // serving: run until interrupted
		return nil
	}
	// Not serving (e.g. replay-to-ledger): exit when the source is exhausted.
	if err := <-collErr; err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// startDetection loads rule packs and (unless disabled) threat feeds. Detection
// is optional: a pack that fails to load must not stop the flight recorder,
// which is useful on its own.
func startDetection(rulesDir string, noFeeds bool) (*detect.Engine, *intel.Store) {
	var packs []*rules.Pack
	load := func(name string, data []byte) {
		p, err := rules.LoadPack(data)
		if err != nil {
			log.Printf("rules: %s failed to load: %v", name, err)
			return
		}
		packs = append(packs, p)
		log.Printf("rules: loaded %s (%d rules)", name, len(p.Rules))
	}

	if rulesDir != "" {
		entries, err := os.ReadDir(rulesDir)
		if err != nil {
			log.Printf("rules: cannot read %s: %v", rulesDir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(rulesDir, e.Name()))
			if err != nil {
				continue
			}
			load(e.Name(), data)
		}
	} else {
		entries, _ := rulesdata.Packs.ReadDir(".")
		for _, e := range entries {
			if filepath.Ext(e.Name()) != ".yaml" {
				continue
			}
			data, err := rulesdata.Packs.ReadFile(e.Name())
			if err != nil {
				continue
			}
			load(e.Name(), data)
		}
	}
	if len(packs) == 0 {
		log.Print("rules: no packs loaded; detection disabled")
		return nil, nil
	}

	var feeds *intel.Store
	if !noFeeds {
		feeds = intel.New()
		go func() {
			ctx := context.Background()
			dir := filepath.Join(baseDir(), "feeds")
			if err := feeds.EnsureLoaded(ctx, dir, intel.DefaultSources); err != nil {
				log.Printf("intel: %v (feed-based rules will not fire)", err)
				return
			}
			feeds.RefreshLoop(ctx, dir, intel.DefaultSources)
		}()
	}
	return detect.New(rules.NewSet(packs...), feeds), feeds
}

// startRecon loads the offline address-ownership dataset in the background.
// It is enrichment, not a dependency: the agent records connections normally
// while the dataset downloads, and rows written before it is ready get their
// ownership filled in as they see further activity.
func startRecon() *recon.DB {
	db := recon.New()
	cache := filepath.Join(baseDir(), "ip2asn.tsv")
	go func() {
		ctx := context.Background()
		if err := db.EnsureLoaded(ctx, cache); err != nil {
			log.Printf("recon: ownership data unavailable (%v); connections will show no owner/country", err)
			return
		}
		log.Printf("recon: address-ownership dataset ready (%s)", cache)
		db.RefreshLoop(ctx, cache)
	}()
	return db
}

func pickSource(replayPath string) (source.EventSource, error) {
	if replayPath != "" {
		log.Printf("source: replay %s", replayPath)
		return source.NewReplaySource(replayPath)
	}
	log.Print("source: live ETW")
	return source.NewETWSource()
}

func sourceName(replayPath string) string {
	if replayPath != "" {
		return "replay"
	}
	return "live-etw"
}

// setupLogging tees log output to a file next to the exe (so a flashed-and-closed
// console still leaves a diagnosable trail) and to stderr.
func setupLogging() func() {
	logPath := filepath.Join(baseDir(), "nitewatch.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open log file %q: %v\n", logPath, err)
		return func() {}
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	log.Printf("=== NiteWatch starting; logging to %s ===", logPath)
	return func() { f.Close() }
}

// holdOpen keeps a double-click console window open long enough to read.
func holdOpen() {
	if runtime.GOOS == "windows" {
		fmt.Fprint(os.Stderr, "\nNiteWatch exited. This window stays open for 15s so you can read the error above.\n")
		time.Sleep(15 * time.Second)
	}
}
