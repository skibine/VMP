// Package metrics runs the background pull-poller: periodically SSHes metrics-enabled VMs (reusing
// internal/ssh) and records samples into the store, plus an hourly downsampling job (§5.2).
//
// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(8): PullPoller; TECH(8): goroutines,ssh]
// @purpose Give VM Pulse continuous CPU/RAM/disk/load history for credentialed VMs without deploying
// an agent — the design's "pull-over-SSH" mode (§5.1). The same metric_samples store + downsampler
// will later receive push-agent data too.
// @io Poller.Run(ctx) blocks; every interval it collects+records for metrics-enabled VMs.
// @invariants
//   - A failed collection (no creds / dial error / parse) for one VM never stops the poller.
//   - Concurrency is bounded by a worker pool (default 4) so the network/server is not hammered.
//   - Only VMs with metrics_enabled=1 (non-archived) are polled.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: poller, metrics, pull-over-ssh, background, worker-pool, collect, record, downsample
// STRUCTURE: ▶ ticker(60s) → ListEnabled → ◇ pool-4 ∋vm: Collect→Record → ⊕ ; hourly → Downsample
package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// Collector pulls one metric sample set for a VM. *ssh.Dialer satisfies this (its Collect method).
type Collector interface {
	Collect(ctx context.Context, vmID int64) (map[string]float64, error)
}

// Poller periodically collects metrics from enabled VMs and records them, plus hourly downsampling.
type Poller struct {
	st       *store.Store
	c        Collector
	logger   *slog.Logger
	interval time.Duration
	workers  int
	keepRaw  time.Duration // raw retention before downsampling (default 7d)
}

// New builds a Poller with sane defaults (60s interval, 4 workers, 7d raw retention).
func New(st *store.Store, c Collector, logger *slog.Logger) *Poller {
	if logger == nil {
		logger = slog.Default()
	}
	return &Poller{st: st, c: c, logger: logger, interval: 60 * time.Second, workers: 4, keepRaw: 7 * 24 * time.Hour}
}

// WithInterval overrides the poll cadence (useful in tests).
func (p *Poller) WithInterval(d time.Duration) *Poller { p.interval = d; return p }

// WithWorkers overrides the worker-pool size.
func (p *Poller) WithWorkers(n int) *Poller {
	if n > 0 {
		p.workers = n
	}
	return p
}

// region FUNC_Poller_Run [DOMAIN(8): Observability; CONCEPT(8): Loop; TECH(7): ticker,select]
// @purpose Run the collection + downsampling loop until ctx is cancelled (called as a goroutine).
// @io (ctx) -> error (ctx.Err() on shutdown)
// @complexity 6
// @invariants
//   - One collection cycle runs immediately on start, then every interval.
//   - Downsampling runs hourly and never blocks collection longer than the cycle itself.
//
// endregion FUNC_Poller_Run
func (p *Poller) Run(ctx context.Context) error {
	logging.LDD(p.logger, 8, "Run", "START", fmt.Sprintf("interval=%s workers=%d", p.interval, p.workers))
	p.cycle(ctx)
	_ = p.downsample(ctx)

	tick := time.NewTicker(p.interval)
	defer tick.Stop()
	down := time.NewTicker(time.Hour)
	defer down.Stop()
	for {
		select {
		case <-tick.C:
			p.cycle(ctx)
		case <-down.C:
			_ = p.downsample(ctx)
		case <-ctx.Done():
			logging.LDD(p.logger, 8, "Run", "STOP", "context cancelled")
			return ctx.Err()
		}
	}
}

// cycle lists metrics-enabled VMs and collects+records each with a bounded worker pool.
func (p *Poller) cycle(ctx context.Context) {
	vms, err := p.st.ListMetricsEnabledVMs(ctx)
	if err != nil {
		logging.LDD(p.logger, 10, "cycle", "LIST_FAIL", err.Error())
		return
	}
	if len(vms) == 0 {
		return
	}
	logging.LDD(p.logger, 7, "cycle", "TICK", fmt.Sprintf("enabled=%d", len(vms)))

	sem := make(chan struct{}, p.workers)
	var wg sync.WaitGroup
	for _, vm := range vms {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(id int64, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			p.pollOne(ctx, id, name)
		}(vm.ID, vm.Name)
	}
	wg.Wait()
}

// pollOne collects a single VM's metrics and records them; any error is logged and swallowed.
func (p *Poller) pollOne(ctx context.Context, id int64, name string) {
	samples, err := p.c.Collect(ctx, id)
	if err != nil {
		logging.LDD(p.logger, 9, "pollOne", "COLLECT_FAIL", fmt.Sprintf("vm=%d(%s): %v", id, name, err))
		return
	}
	if err := p.st.RecordSamples(ctx, id, samples); err != nil {
		logging.LDD(p.logger, 10, "pollOne", "RECORD_FAIL", err.Error())
		return
	}
	logging.LDD(p.logger, 7, "pollOne", "RECORDED", fmt.Sprintf("vm=%d(%s) metrics=%d", id, name, len(samples)))
}

func (p *Poller) downsample(ctx context.Context) error {
	removed, err := p.st.Downsample(ctx, p.keepRaw)
	if err != nil {
		logging.LDD(p.logger, 9, "downsample", "FAIL", err.Error())
		return err
	}
	logging.LDD(p.logger, 7, "downsample", "DONE", fmt.Sprintf("raw_removed=%d", removed))
	return nil
}
