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
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/platform"
	"github.com/threattape/nitewatch/agent/internal/source"
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
		replayPath = flag.String("replay", "", "replay events from a .jsonl trace instead of live ETW")
		serve      = flag.Bool("serve", true, "serve the localhost dashboard + API")
		open       = flag.Bool("open", true, "open the dashboard in a browser when serving (Windows)")
		dbPath     = flag.String("db", filepath.Join(baseDir(), "nitewatch.db"), "path to the connection ledger database")
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
	log.Printf("env: os=%s arch=%s elevated=%v", runtime.GOOS, runtime.GOARCH, platform.IsElevated())
	if exe, err := os.Executable(); err == nil {
		log.Printf("env: exe=%s", exe)
	}

	if err := run(*replayPath, *serve, *open, *dbPath); err != nil {
		log.Printf("fatal: %v", err)
		holdOpen()
		os.Exit(1)
	}
}

func run(replayPath string, serve, open bool, dbPath string) error {
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start the dashboard first so it is reachable even if the sensor can't start.
	var srv *api.Server
	if serve {
		srv = api.New(led)
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

	coll := collector.New(src, led)
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
