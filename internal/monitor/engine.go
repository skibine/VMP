// Package monitor — engine (dispatcher + worker pool + result writer).
//
// region MODULE_CONTRACT [DOMAIN(8): Monitoring; CONCEPT(8): PlaneAEngine; TECH(9): goroutines]
// @purpose Run enabled checks on schedule and persist results. This is the Plane A core:
//
//	always-on, no master passphrase, no SSH credentials (foundation-v2 §3).
//
// @io New(store, registry, logger, Options) -> *Engine ; Start(ctx) ; Stop()
// @uses internal/store, internal/logging, sync, time
// @invariants
//   - Engine NEVER holds SSH credentials or depends on the credential vault.
//   - Stop() fully drains: dispatcher+retention return, workers drain jobs, then return.
//   - A disabled check is never scheduled.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: engine, dispatcher, worker pool, scheduler, tick, results, Plane A, lifecycle
// STRUCTURE: ▶ Start → ○ dispatch(tick→jobs) + N workers(runCheck→store) + retention ; Stop → drain
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// region STRUCT_Options [DOMAIN(7): Monitoring; CONCEPT(6): Config; TECH(5): struct]
// @purpose Tunables for the engine (pool size, scheduler resolution, retention window).
// endregion STRUCT_Options
type Options struct {
	PoolSize      int
	TickEvery     time.Duration
	RetentionDays int
}

// DefaultOptions returns sane defaults: 8 workers, 5s scheduler, 30-day retention.
func DefaultOptions() Options {
	return Options{PoolSize: 8, TickEvery: 5 * time.Second, RetentionDays: 30}
}

// region STRUCT_Engine [DOMAIN(8): Monitoring; CONCEPT(7): Orchestrator; TECH(8): goroutines]
// @purpose Own the dispatcher, worker pool, retention job, and per-check last-run state.
// endregion STRUCT_Engine
type Engine struct {
	store         *store.Store
	reg           *Registry
	logger        *slog.Logger
	poolSize      int
	tickEvery     time.Duration
	retentionDays int

	jobs      chan store.Check
	workerWg  sync.WaitGroup
	bgWg      sync.WaitGroup // dispatcher + retention
	ctx       context.Context
	cancel    context.CancelFunc
	lastMu    sync.Mutex
	last      map[int64]time.Time
	startedMu sync.Mutex
	started   bool
}

// region FUNC_New [DOMAIN(7): Monitoring; CONCEPT(6): Build; TECH(5): struct]
// @purpose Construct an Engine with clamped options.
// @complexity 2
// endregion FUNC_New
func New(s *store.Store, reg *Registry, logger *slog.Logger, opts Options) *Engine {
	if opts.PoolSize < 1 {
		opts.PoolSize = 1
	}
	if opts.TickEvery < 100*time.Millisecond {
		opts.TickEvery = 100 * time.Millisecond
	}
	if opts.RetentionDays < 1 {
		opts.RetentionDays = 30
	}
	return &Engine{
		store: s, reg: reg, logger: logger,
		poolSize: opts.PoolSize, tickEvery: opts.TickEvery, retentionDays: opts.RetentionDays,
		last: map[int64]time.Time{},
	}
}

// region FUNC_Start [DOMAIN(7): Monitoring; CONCEPT(7): Lifecycle; TECH(7): goroutines]
// @purpose Launch workers, dispatcher and retention job under the given parent context.
// @complexity 5
// endregion FUNC_Start
func (e *Engine) Start(parent context.Context) {
	e.startedMu.Lock()
	defer e.startedMu.Unlock()
	if e.started {
		return
	}
	e.ctx, e.cancel = context.WithCancel(parent)
	e.jobs = make(chan store.Check, e.poolSize*4)
	for i := 0; i < e.poolSize; i++ {
		e.workerWg.Add(1)
		go e.worker()
	}
	e.bgWg.Add(2)
	go e.dispatch()
	go e.retention()
	e.started = true
	logging.LDD(e.logger, 9, "Start", "STARTED",
		fmt.Sprintf("pool=%d tick=%s retention=%dd", e.poolSize, e.tickEvery, e.retentionDays))
}

// region FUNC_Stop [DOMAIN(7): Monitoring; CONCEPT(7): Lifecycle; TECH(7): goroutines]
// @purpose Cancel context, wait for dispatcher+retention to stop, close jobs, drain workers.
// @complexity 4
// @invariants
//   - Returns only after all engine goroutines have exited.
//
// endregion FUNC_Stop
func (e *Engine) Stop() {
	e.startedMu.Lock()
	if !e.started {
		e.startedMu.Unlock()
		return
	}
	e.started = false
	e.startedMu.Unlock()

	e.cancel()
	e.bgWg.Wait() // dispatcher + retention no longer write to jobs
	close(e.jobs)
	e.workerWg.Wait() // workers finish draining
	logging.LDD(e.logger, 9, "Stop", "STOPPED", "engine drained")
}

// dispatch is the scheduler: every TickEvery it enqueues due checks.
func (e *Engine) dispatch() {
	defer e.bgWg.Done()
	ticker := time.NewTicker(e.tickEvery)
	defer ticker.Stop()
	e.tick()
	for {
		select {
		case <-ticker.C:
			e.tick()
		case <-e.ctx.Done():
			return
		}
	}
}

// tick reads enabled checks and enqueues those whose interval has elapsed.
func (e *Engine) tick() {
	checks, err := e.store.ListChecks(e.ctx, nil)
	if err != nil {
		logging.LDD(e.logger, 10, "tick", "LIST_FAIL", err.Error())
		return
	}
	now := time.Now()
	enqueued := 0
	for _, c := range checks {
		if !c.Enabled {
			continue
		}
		if now.Sub(e.lastRun(c.ID)) < time.Duration(c.IntervalSec)*time.Second {
			continue
		}
		e.setLastRun(c.ID, now)
		select {
		case e.jobs <- c:
			enqueued++
		case <-e.ctx.Done():
			return
		}
	}
	if enqueued > 0 {
		logging.LDD(e.logger, 8, "tick", "ENQUEUED", fmt.Sprintf("%d checks", enqueued))
	}
}

// worker pulls checks and executes them until the jobs channel is closed.
func (e *Engine) worker() {
	defer e.workerWg.Done()
	for c := range e.jobs {
		e.runCheck(c)
	}
}

// region FUNC_runCheck [DOMAIN(8): Monitoring; CONCEPT(8): Execute; TECH(7): Checker]
// @purpose Delegate a scheduled check to the shared executor.
// endregion FUNC_runCheck
func (e *Engine) runCheck(c store.Check) {
	_, _ = ExecuteCheck(e.ctx, e.store, e.reg, e.logger, c)
}

// region FUNC_ExecuteCheck [DOMAIN(8): Monitoring; CONCEPT(8): Execute; TECH(7): Checker]
// @purpose Resolve target, run checker, apply thresholds, persist result. Shared by the engine
//
//	and the "run now" endpoint.
//
// @complexity 6
// endregion FUNC_ExecuteCheck
func ExecuteCheck(ctx context.Context, s *store.Store, reg *Registry, logger *slog.Logger, c store.Check) (Result, error) {
	target, err := resolveTarget(ctx, s, c)
	if err != nil {
		res := Result{Status: StatusUnknown, Message: "resolve target: " + err.Error()}
		persistResult(ctx, s, logger, c.ID, res)
		return res, err
	}
	chk, ok := reg.Get(c.CheckType)
	if !ok {
		res := Result{Status: StatusUnknown, Message: "no checker for type: " + c.CheckType}
		persistResult(ctx, s, logger, c.ID, res)
		return res, fmt.Errorf("no checker for type: %s", c.CheckType)
	}
	res := chk.Run(ctx, target, c.Params)
	res = applyThresholds(res, c.Thresholds)
	persistResult(ctx, s, logger, c.ID, res)
	return res, nil
}

// region FUNC_RunProbe [DOMAIN(8): Monitoring; CONCEPT(7): AdHoc; TECH(6): Checker]
// @purpose Run a single ad-hoc probe (diagnostics) WITHOUT persisting. Returns the Result.
// @complexity 3
// endregion FUNC_RunProbe
func RunProbe(ctx context.Context, reg *Registry, checkType, target string, params map[string]any) (Result, error) {
	chk, ok := reg.Get(checkType)
	if !ok {
		return Result{Status: StatusUnknown, Message: "no checker for type: " + checkType}, fmt.Errorf("no checker for type: %s", checkType)
	}
	return chk.Run(ctx, target, params), nil
}

// persistResult writes a result and logs the outcome.
func persistResult(ctx context.Context, s *store.Store, logger *slog.Logger, checkID int64, res Result) {
	if _, err := s.InsertCheckResult(ctx, checkID, string(res.Status), res.LatencyMS, res.Message, res.Detail); err != nil {
		logging.LDD(logger, 10, "persist", "INSERT_FAIL", err.Error())
		return
	}
	logging.LDD(logger, 8, "runCheck", "RESULT",
		fmt.Sprintf("check=%d status=%s lat=%.2fms", checkID, res.Status, res.LatencyMS))
}

// resolveTarget returns the probe target string (vm IP/hostname or domain name).
func resolveTarget(ctx context.Context, s *store.Store, c store.Check) (string, error) {
	switch c.TargetType {
	case "vm":
		if c.VMID == nil {
			return "", fmt.Errorf("vm check without vm_id")
		}
		vm, err := s.GetVM(ctx, *c.VMID)
		if err != nil {
			return "", err
		}
		if vm.IP != "" {
			return vm.IP, nil
		}
		return vm.Hostname, nil
	case "domain":
		if c.DomainID == nil {
			return "", fmt.Errorf("domain check without domain_id")
		}
		d, err := s.GetDomain(ctx, *c.DomainID)
		if err != nil {
			return "", err
		}
		return d.Name, nil
	}
	return "", fmt.Errorf("unknown target_type: %s", c.TargetType)
}

// retention periodically prunes old check_results.
func (e *Engine) retention() {
	defer e.bgWg.Done()
	e.prune()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.prune()
		case <-e.ctx.Done():
			return
		}
	}
}

func (e *Engine) prune() {
	n, err := e.store.RetentionDeleteResults(e.ctx, e.retentionDays)
	if err != nil {
		logging.LDD(e.logger, 10, "prune", "FAIL", err.Error())
		return
	}
	if n > 0 {
		logging.LDD(e.logger, 8, "prune", "PRUNED", fmt.Sprintf("%d rows older than %dd", n, e.retentionDays))
	}
}

func (e *Engine) lastRun(id int64) time.Time {
	e.lastMu.Lock()
	defer e.lastMu.Unlock()
	return e.last[id]
}

func (e *Engine) setLastRun(id int64, t time.Time) {
	e.lastMu.Lock()
	defer e.lastMu.Unlock()
	e.last[id] = t
}
