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
	"syscall"
	"time"

	"github.com/threattape/nitewatch/agent/internal/api"
	"github.com/threattape/nitewatch/agent/internal/collector"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/platform"
	"github.com/threattape/nitewatch/agent/internal/source"
)

var version = "0.1.0-dev"

func main() {
	var (
		replayPath = flag.String("replay", "", "replay events from a .jsonl trace instead of live ETW")
		serve      = flag.Bool("serve", true, "serve the localhost dashboard + API")
		open       = flag.Bool("open", true, "open the dashboard in a browser when serving (Windows)")
		dbPath     = flag.String("db", defaultDBPath(), "path to the connection ledger database")
	)
	flag.Parse()

	closeLog := setupLogging()
	defer closeLog()

	log.Printf("NiteWatch agent %s", version)
	if err := run(*replayPath, *serve, *open, *dbPath); err != nil {
		log.Printf("fatal: %v", err)
		// Give a double-click user a beat to read the console before it closes.
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}
}

func run(replayPath string, serve, open bool, dbPath string) error {
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create ledger dir: %w", err)
		}
	}
	led, err := ledger.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}
	defer led.Close()
	log.Printf("ledger: %s", dbPath)

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

// setupLogging tees log output to a file (so a flashed-and-closed console still
// leaves a diagnosable trail) and to stderr. Returns a close func.
func setupLogging() func() {
	logPath := filepath.Join(logDir(), "nitewatch.log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return func() {}
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	log.Printf("logging to %s", logPath)
	return func() { f.Close() }
}

func logDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "NiteWatch")
		}
	}
	return "."
}

func defaultDBPath() string {
	return filepath.Join(logDir(), "ledger.db")
}
