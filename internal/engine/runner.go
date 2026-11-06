package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

type Snapshot struct {
	State            string    `json:"state"`
	ProfileID        string    `json:"profileId,omitempty"`
	Engine           string    `json:"engine,omitempty"`
	PID              int       `json:"pid,omitempty"`
	StartedAt        time.Time `json:"startedAt,omitempty"`
	LastError        string    `json:"lastError,omitempty"`
	LifecyclePending bool      `json:"lifecyclePending,omitempty"`
	Log              []string  `json:"log"`
}

// Summary excludes user identifiers, paths and child output from support metadata.
type Summary struct {
	State        string `json:"state"`
	Engine       string `json:"engine,omitempty"`
	ErrorPresent bool   `json:"errorPresent"`
	LogLines     int    `json:"logLines"`
}

func (m *Manager) Summary() Summary {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, errorPresent := m.state.State, m.state.LastError != ""
	if m.cmd != nil && m.run != nil && m.run.owner != nil && m.run.owner.pendingError() != nil {
		state, errorPresent = "error", true
	}
	return Summary{State: state, Engine: m.state.Engine, ErrorPresent: errorPresent, LogLines: len(m.log)}
}

// RunReason describes the observed terminal state of one launched process.
// A stop signal accepted before publication does not prove it caused the exit.
type RunReason string

const (
	RunExited        RunReason = "exited"
	RunFailed        RunReason = "failed"
	RunStopped       RunReason = "stopped"
	RunPolicyRevoked RunReason = "policy-revoked"
)

var ErrRunUnavailable = errors.New("engine launch handle is unavailable")

// RunResult retains the actual cmd.Wait error separately from policy revocation
// and lifecycle observation or cleanup uncertainty.
// It contains process errors for the local caller, not audit or support metadata.
type RunResult struct {
	Reason       RunReason
	WaitErr      error
	PolicyErr    error
	LifecycleErr error
}

// Run identifies exactly one successful launch, even after another launch starts.
// Its terminal result is published once, before Done closes. Copies of a handle
// share the same launch and terminal result.
type Run struct {
	state *runState
}

type runState struct {
	owner        processLifetime
	done         chan struct{}
	result       RunResult
	stopAccepted bool          // guarded by the manager mutex
	stopPending  chan struct{} // guarded by the manager mutex
}

// Done is nil for a nil or zero Run. It signals terminal observation, not merely
// launch acceptance or a stop request.
func (r *Run) Done() <-chan struct{} {
	if r == nil {
		return nil
	}
	if r.state == nil {
		return nil
	}
	return r.state.done
}

// Wait cancels only this wait; it never signals the owned process. A published
// terminal result takes precedence over an already canceled waiting context.
func (r *Run) Wait(ctx context.Context) (RunResult, error) {
	if r == nil || r.state == nil || r.state.done == nil {
		return RunResult{}, ErrRunUnavailable
	}
	select {
	case <-r.state.done:
		return r.state.result, nil
	default:
	}
	select {
	case <-r.state.done:
		return r.state.result, nil
	case <-ctx.Done():
		return RunResult{}, ctx.Err()
	}
}

// PendingError is a fixed nonterminal fault, not an exit result. A caller must
// still retain and drain this exact Run; no new numeric-PID action is authorized.
func (r *Run) PendingError() error {
	if r == nil || r.state == nil || r.state.owner == nil {
		return nil
	}
	return r.state.owner.pendingError()
}
func (r *Run) Fault() <-chan struct{} {
	if r == nil || r.state == nil || r.state.owner == nil {
		return nil
	}
	return r.state.owner.faultSignal()
}

// managerShutdown is created once under Manager.mu. The captured generation is
// completed by one worker; err is published before done closes.
type managerShutdown struct {
	done     chan struct{}
	entryRun *runState
	run      *runState
	err      error
}

type Manager struct {
	guard                 *managed.Guard
	opMu                  operationMutex // Serializes prepare/start/stop, including generated files.
	mu                    sync.Mutex
	cmd                   *exec.Cmd
	run                   *runState
	state                 Snapshot
	log                   []string
	root                  string
	closing               bool
	shutdown              *managerShutdown
	preparationFault      error // Sticky unconfirmed pre-start cleanup; no child Run.
	prepareLifetime       lifetimeFactory
	output                io.Writer
	afterStart            func() // Private source-test observer, fixed before Start.
	beforeShutdownCapture func() // Private source-test observer, fixed before Shutdown.
}

func NewManager(root string) *Manager { return NewManagerWithGuard(root, managed.NewGuard(nil)) }
func NewManagerWithGuard(root string, guard *managed.Guard) *Manager {
	return &Manager{guard: guard, root: root, state: Snapshot{State: "stopped", Log: []string{}}, log: make([]string, 0, 150)}
}
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state
	if m.cmd != nil && m.run != nil && m.run.owner != nil {
		if fault := m.run.owner.pendingError(); fault != nil {
			s.State = "error"
			s.LastError = fault.Error()
			s.PID = 0
			s.LifecyclePending = true
		}
	}
	s.Log = append([]string{}, m.log...)
	return s
}
func (m *Manager) addLog(line string) { m.mu.Lock(); defer m.mu.Unlock(); m.addLogLocked(line) }
func (m *Manager) addLogLocked(line string) {
	// Child output is untrusted text. Strip terminal control characters before
	// showing it in either the browser or a console.
	line = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		if r == 127 {
			return -1
		}
		return r
	}, line)
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if len(line) > 2000 {
		line = line[:2000] + "\u2026"
	}
	m.log = append(m.log, time.Now().Format("15:04:05")+"  "+line)
	if len(m.log) > 150 {
		m.log = append([]string(nil), m.log[len(m.log)-150:]...)
	}
}

type logWriter struct{ m *Manager }

func (w logWriter) Write(b []byte) (int, error) {
	s := string(b)
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			w.m.addLog(line)
		}
	}
	return len(b), nil
}

// Start preserves the launch-acceptance contract for existing controller callers.
func (m *Manager) Start(p profile.Profile) error {
	return m.StartContext(context.Background(), p)
}

func (m *Manager) StartContext(ctx context.Context, p profile.Profile) error {
	_, err := m.StartTrackedContext(ctx, p)
	return err
}

// StartTracked returns a handle only after the owned process starts successfully.
// Successful launch is not a connectivity or service-readiness observation.
func (m *Manager) StartTracked(p profile.Profile) (*Run, error) {
	return m.StartTrackedContext(context.Background(), p)
}

// The caller context controls admission/preparation only. Once Start succeeds,
// the exact owned Run is returned, even if that caller has canceled meanwhile.
// Child lifetime remains governed by managed authorization and explicit Stop.
func (m *Manager) StartTrackedContext(ctx context.Context, p profile.Profile) (*Run, error) {
	return m.startTrackedContext(ctx, p, nil)
}

// observedWait is an in-process test observer; it cannot alter process waiting.
func (m *Manager) startTracked(p profile.Profile, observedWait func()) (*Run, error) {
	return m.startTrackedContext(context.Background(), p, observedWait)
}

func (m *Manager) startTrackedContext(caller context.Context, p profile.Profile, observedWait func()) (*Run, error) {
	if err := m.pendingLifetimeError(); err != nil {
		return nil, err
	}
	if err := m.opMu.LockContext(caller); err != nil {
		return nil, err
	}
	defer m.opMu.Unlock()
	if err := m.pendingLifetimeError(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return nil, errors.New("engine manager is shutting down")
	}
	if m.cmd != nil {
		m.mu.Unlock()
		return nil, errors.New("another engine is running; stop it before starting a new one")
	}
	m.mu.Unlock()
	bin, args, err := prepareWithGuardContext(caller, p, m.root, m.guard)
	if err != nil {
		return nil, err
	}
	if err := preparationContextError(caller); err != nil {
		return nil, err
	}
	environment, authorization, err := launchPolicyAuthorization(m.guard, p, bin)
	if err != nil {
		return nil, err
	}
	ctx, cancel, err := authorization.Context(context.Background())
	if err != nil {
		return nil, err
	}
	started := false
	defer func() {
		if !started {
			cancel()
		}
	}()

	// A plain Unix command has no hidden context watcher or delayed PID kill.
	// Windows retains its existing CommandContext/handle behavior.
	cmd := newEngineCommand(ctx, bin, args)
	cmd.Dir = filepath.Dir(bin)
	cmd.WaitDelay = 2 * time.Second
	configureProcess(cmd)
	output := m.output
	if output == nil {
		output = logWriter{m}
	}
	cmd.Stdout, cmd.Stderr = output, output
	cmd.Env = environment
	factory := m.prepareLifetime
	if factory == nil {
		factory = prepareProcessLifetime
	}
	if err := preparationContextError(caller); err != nil {
		return nil, err
	}
	owner, err := factory(cmd)
	if err != nil {
		if owner != nil {
			return nil, m.abortPreparedOwner(owner, err)
		}
		return nil, m.rememberPreparationFailure(err)
	}
	if owner == nil {
		return nil, ErrProcessLifecycle
	}
	run := &runState{done: make(chan struct{}), owner: owner}
	owner.setFaultHandler(func(fault error) {
		m.mu.Lock()
		if m.run == run && m.cmd == cmd {
			m.state.State = "error"
			m.state.LastError = fault.Error()
			m.state.PID = 0
		}
		m.mu.Unlock()
	})
	m.mu.Lock()
	closing, occupied := m.closing, m.cmd != nil
	m.mu.Unlock()
	callerErr := preparationContextError(caller)
	if closing || occupied || ctx.Err() != nil || callerErr != nil {
		var primary error
		switch {
		case closing:
			primary = errors.New("engine manager is shutting down")
		case occupied:
			primary = errors.New("another engine is running; stop it before starting a new one")
		case callerErr != nil:
			primary = &preparationCancellation{cause: errors.Join(ctx.Err(), callerErr)}
		default:
			primary = ctx.Err()
		}
		return nil, m.abortPreparedOwner(owner, primary)
	}

	// Never hold Manager.mu across Start: child output uses that mutex.
	if err := cmd.Start(); err != nil {
		if cause := context.Cause(ctx); managed.IsPolicyError(cause) {
			err = errors.Join(cause, err)
		}
		return nil, m.abortPreparedOwner(owner, fmt.Errorf("engine start failed: %w", err))
	}
	started = true
	if m.afterStart != nil {
		// The real child already executed. The observer cannot replace it, and
		// publication must still proceed if Shutdown sets closing meanwhile.
		m.afterStart()
	}
	// Successful Start is always an accepted, nonnil owned Run. Even a concurrent
	// Shutdown or observer failure cannot erase a child that already executed.
	m.mu.Lock()
	m.cmd, m.run = cmd, run
	m.state = Snapshot{State: "running", ProfileID: p.ID, Engine: p.Engine, PID: cmd.Process.Pid, StartedAt: time.Now().UTC()}
	m.log = nil
	m.addLogLocked("Engine process launched; service/network connectivity is NOT yet verified")
	m.mu.Unlock()
	go func() {
		waitErr, lifecycleErr := owner.wait(ctx)
		cause := context.Cause(ctx)
		policyFailure := managed.IsPolicyError(cause)
		cancel()
		if observedWait != nil {
			observedWait()
		}
		m.mu.Lock()
		for run.stopPending != nil {
			pending := run.stopPending
			m.mu.Unlock()
			<-pending
			m.mu.Lock()
		}
		result := RunResult{Reason: RunExited, WaitErr: waitErr, LifecycleErr: lifecycleErr}
		if policyFailure {
			result.Reason = RunPolicyRevoked
			result.PolicyErr = cause
		} else if lifecycleErr != nil {
			result.Reason = RunFailed
		} else if run.stopAccepted {
			result.Reason = RunStopped
		} else if waitErr != nil {
			result.Reason = RunFailed
		}
		failed := result.Reason == RunFailed || result.Reason == RunPolicyRevoked
		terminalErr := errors.Join(result.PolicyErr, result.WaitErr, result.LifecycleErr)
		if m.cmd == cmd {
			m.cmd = nil
			m.state.State = "stopped"
			m.state.PID = 0
			if failed {
				m.state.State = "error"
				m.state.LastError = terminalErr.Error()
			}
		}
		if failed {
			m.addLogLocked("Engine process exited: " + terminalErr.Error())
		} else {
			m.addLogLocked("Engine process exited normally")
		}
		run.result = result
		close(run.done)
		m.mu.Unlock()
	}()
	return &Run{state: run}, nil
}

func (m *Manager) Stop() error {
	return m.stop(interruptProcess, killProcess, 3*time.Second, time.Second)
}

// The seams permit deterministic source tests without altering native defaults.
func (m *Manager) stop(interrupt, kill func(*os.Process) error, grace, forceWait time.Duration) error {
	if err := m.pendingLifetimeError(); err != nil {
		return err
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.stopLocked(interrupt, kill, grace, forceWait)
}

// stopLocked shares the normal stop path with the sole shutdown worker. Its
// caller holds opMu; native calls and terminal waits never hold Manager.mu.
func (m *Manager) stopLocked(interrupt, kill func(*os.Process) error, grace, forceWait time.Duration) error {
	if err := m.pendingLifetimeError(); err != nil {
		return err
	}
	m.mu.Lock()
	cmd := m.cmd
	run := m.run
	m.mu.Unlock()
	if cmd == nil {
		return nil
	}
	signalErr := m.dispatchStop(cmd, run, func(process *os.Process) error {
		if err := interrupt(process); err != nil {
			if processOwnershipLost(err) {
				return err
			}
			return kill(process)
		}
		return nil
	})
	if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
		return signalErr
	}
	select {
	case <-run.done:
		return nil
	case <-time.After(grace):
		forceErr := m.dispatchStop(cmd, run, kill)
		if errors.Is(forceErr, ErrProcessCleanupPending) || errors.Is(forceErr, ErrProcessOwnershipLost) {
			return forceErr
		}
		select {
		case <-run.done:
			return nil
		case <-time.After(forceWait):
			return errors.New("engine did not exit within timeout")
		}
	}
}

// Caller holds opMu. Native calls stay outside mu. Publication waits for their
// resolved result, including escalation, and cannot confuse an accepted signal
// with a failed attempt. Native signal calls themselves have no hard deadline.
func (m *Manager) dispatchStop(cmd *exec.Cmd, run *runState, signal func(*os.Process) error) error {
	m.mu.Lock()
	if m.cmd != cmd || m.run != run {
		m.mu.Unlock()
		return os.ErrProcessDone
	}
	pending := make(chan struct{})
	run.stopPending = pending
	m.state.State = "stopping"
	m.mu.Unlock()
	err := run.owner.dispatch(signal)
	m.mu.Lock()
	if err == nil {
		run.stopAccepted = true
	}
	run.stopPending = nil
	if m.cmd == cmd && !run.stopAccepted {
		if fault := run.owner.pendingError(); fault != nil {
			m.state.State = "error"
			m.state.LastError = fault.Error()
			m.state.PID = 0
		} else {
			m.state.State = "running"
		}
	}
	close(pending)
	m.mu.Unlock()
	return err
}
func (m *Manager) pendingLifetimeError() error {
	m.mu.Lock()
	run := m.run
	active := m.cmd != nil
	fault := m.preparationFault
	m.mu.Unlock()
	if active && run != nil && run.owner != nil {
		if pending := run.owner.pendingError(); pending != nil {
			return pending
		}
	}
	return fault
}

// RetryCleanup is an explicit, generation-bound recovery for known retained
// identity only. Success authorizes waiting for this Run, not a replacement.
func (m *Manager) RetryCleanup(handle *Run) error {
	if handle == nil || handle.state == nil {
		return ErrRunUnavailable
	}
	if errors.Is(handle.PendingError(), ErrProcessOwnershipLost) {
		return ErrProcessOwnershipLost
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	current := m.run == handle.state && m.cmd != nil
	m.mu.Unlock()
	if !current {
		return ErrRunUnavailable
	}
	return handle.state.owner.retryCleanup()
}

// Shutdown rejects new starts and joins one retained shutdown worker. A caller
// timeout cancels only that caller's wait. Even after a failed stop, the worker
// keeps the exact active generation until its real terminal result is observed.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closing = true
	shutdown := m.shutdown
	startWorker := shutdown == nil
	if startWorker {
		shutdown = &managerShutdown{done: make(chan struct{}), entryRun: m.run}
		// Capture before a concurrent Stop can finish and clear this active run.
		// Inactive historical runs must not contaminate a no-engine shutdown.
		if m.cmd != nil {
			shutdown.run = m.run
		}
		m.shutdown = shutdown
	}
	m.mu.Unlock()
	if startWorker {
		go m.finishShutdown(shutdown)
	}
	// A previously published terminal result takes precedence over an already
	// canceled caller context, just as Run.Wait does.
	select {
	case <-shutdown.done:
		return shutdown.err
	default:
	}
	select {
	case <-shutdown.done:
		return shutdown.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) finishShutdown(shutdown *managerShutdown) {
	if m.beforeShutdownCapture != nil {
		m.beforeShutdownCapture()
	}
	m.opMu.Lock()
	m.mu.Lock()
	// An in-flight successful Start may publish and even terminate after
	// Shutdown set closing, before this worker acquires opMu. Capture a changed
	// generation even if cmd is already nil; unchanged inactive history stays
	// excluded. Closing prevents any later launch replacing that generation.
	if shutdown.run == nil && (m.cmd != nil || m.run != shutdown.entryRun) {
		shutdown.run = m.run
	}
	m.mu.Unlock()
	stopErr := m.stopLocked(interruptProcess, killProcess, 3*time.Second, time.Second)
	m.opMu.Unlock()

	// Recovery of a known retained owner remains explicit and generation-bound.
	// Never hold opMu while draining: RetryCleanup needs it, and ownership loss
	// deliberately leaves this worker and the exact Run pending indefinitely.
	var result RunResult
	var waitErr error
	if shutdown.run != nil {
		result, waitErr = (&Run{state: shutdown.run}).Wait(context.Background())
	}
	terminalErr := errors.Join(result.PolicyErr, result.LifecycleErr)
	if result.Reason == RunFailed || result.Reason == RunPolicyRevoked {
		terminalErr = errors.Join(terminalErr, result.WaitErr)
	}
	// Expected accepted-stop signal exits remain local success. The actual
	// WaitErr in RunResult is never changed or discarded from the Run itself.
	shutdown.err = errors.Join(stopErr, waitErr, terminalErr)
	close(shutdown.done)
}

func (m *Manager) Preview(p profile.Profile) (LaunchPlan, error) {
	return m.PreviewContext(context.Background(), p)
}

func (m *Manager) PreviewContext(ctx context.Context, p profile.Profile) (LaunchPlan, error) {
	return previewWithGuardContext(ctx, p, m.root, m.guard)
}
