// Command nitewatch is the NiteWatch flight-recorder agent.
//
// Run modes:
//
//	nitewatch --serve                    real ETW source (Windows, elevated)
//	nitewatch --replay <file> --serve    replay a .jsonl trace (any OS, dev/demo)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/threattape/nitewatch/agent/internal/api"
	"github.com/threattape/nitewatch/agent/internal/collector"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/source"
)

var version = "0.1.0-dev"

func main() {
	var (
		replayPath = flag.String("replay", "", "replay events from a .jsonl trace instead of live ETW")
		serve      = flag.Bool("serve", false, "serve the localhost dashboard + API")
		dbPath     = flag.String("db", defaultDBPath(), "path to the connection ledger database")
	)
	flag.Parse()

	log.Printf("NiteWatch agent %s", version)

	if err := run(*replayPath, *serve, *dbPath); err != nil {
		log.Fatalf("nitewatch: %v", err)
	}
}

func run(replayPath string, serve bool, dbPath string) error {
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

	src, err := pickSource(replayPath)
	if err != nil {
		return err
	}
	defer src.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	coll := collector.New(src, led)
	go func() {
		if err := coll.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("collector stopped: %v", err)
		}
	}()

	if serve {
		srv := api.New(led)
		log.Printf("dashboard: http://%s", srv.Addr())
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				log.Printf("server stopped: %v", err)
			}
		}()
	}

	<-ctx.Done()
	log.Print("shutting down")
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

func defaultDBPath() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "NiteWatch", "ledger.db")
		}
	}
	return "nitewatch.db"
}
