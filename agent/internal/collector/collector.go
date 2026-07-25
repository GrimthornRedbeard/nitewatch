// Package collector is the orchestration loop: it pulls normalized events off a
// source, ingests them into the causal window, and records every outbound
// connection — enriched with the domain joined from DNS — into the ledger.
package collector

import (
	"context"

	"github.com/threattape/nitewatch/agent/internal/event"
	"github.com/threattape/nitewatch/agent/internal/graph"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/source"
)

type Collector struct {
	src    source.EventSource
	window *graph.Window
	ledger *ledger.DB
}

// New builds a collector over a source and ledger with a default-sized window.
func New(src source.EventSource, led *ledger.DB) *Collector {
	return &Collector{
		src:    src,
		window: graph.NewWindow(graph.WindowConfig{}),
		ledger: led,
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
	domain := c.window.Current().DomainFor(id)
	_ = c.ledger.RecordConnection(ledger.Connection{
		Time:       e.Time,
		PID:        e.PID,
		Image:      e.Image,
		RemoteIP:   e.RemoteIP,
		RemotePort: e.RemotePort,
		Proto:      e.Proto,
		Domain:     domain,
	})
}
