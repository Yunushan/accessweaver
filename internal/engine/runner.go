package engine

import (
	"context"
	"errors"
	"fmt"
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
	State     string    `json:"state"`
	ProfileID string    `json:"profileId,omitempty"`
	Engine    string    `json:"engine,omitempty"`
	PID       int       `json:"pid,omitempty"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	LastError string    `json:"lastError,omitempty"`
	Log       []string  `json:"log"`
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
	return Summary{State: m.state.State, Engine: m.state.Engine, ErrorPresent: m.state.LastError != "", LogLines: len(m.log)}
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

// RunResult retains the actual cmd.Wait error separately from policy revocation.
// It contains process errors for the local caller, not audit or support metadata.
type RunResult struct {
	Reason    RunReason
	WaitErr   error
	PolicyErr error
}

// Run identifies exactly one successful launch, even after another launch starts.
// Its terminal result is published once, before Done closes. Copies of a handle
// share the same launch and terminal result.
type Run struct {
	state *runState
}

type runState struct {
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

type Manager struct {
	guard   *managed.Guard
	opMu    sync.Mutex // Serializes prepare/start/stop, including generated files.
	mu      sync.Mutex
	cmd     *exec.Cmd
	run     *runState
	state   Snapshot
	log     []string
	root    string
	closing bool
}

func NewManager(root string) *Manager { return NewManagerWithGuard(root, managed.NewGuard(nil)) }
func NewManagerWithGuard(root string, guard *managed.Guard) *Manager {
	return &Manager{guard: guard, root: root, state: Snapshot{State: "stopped", Log: []string{}}, log: make([]string, 0, 150)}
}
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state
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
		line = line[:2000] + "…"
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
	_, err := m.StartTracked(p)
	return err
}

// StartTracked returns a handle only after the owned process starts successfully.
// Successful launch is not a connectivity or service-readiness observation.
func (m *Manager) StartTracked(p profile.Profile) (*Run, error) {
	return m.startTracked(p, nil)
}

// observedWait is an in-process test observer; it cannot alter process waiting.
func (m *Manager) startTracked(p profile.Profile, observedWait func()) (*Run, error) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
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
	bin, args, err := prepareWithGuard(p, m.root, m.guard)
	if err != nil {
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
	// External executables are only started following an explicit user action.
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Dir(bin)
	cmd.WaitDelay = 2 * time.Second
	configureProcess(cmd)
	// Revoke the same owned foreground process/group as normal termination.
	cmd.Cancel = func() error { return killProcess(cmd.Process) }
	cmd.Stdout = logWriter{m}
	cmd.Stderr = logWriter{m}
	cmd.Env = environment
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return nil, errors.New("engine manager is shutting down")
	}
	if m.cmd != nil {
		return nil, errors.New("another engine started concurrently")
	}
	if err := cmd.Start(); err != nil {
		if cause := context.Cause(ctx); managed.IsPolicyError(cause) {
			err = errors.Join(cause, err)
		}
		return nil, fmt.Errorf("engine start failed: %w", err)
	}
	started = true
	m.cmd = cmd
	run := &runState{done: make(chan struct{})}
	m.run = run
	m.state = Snapshot{State: "running", ProfileID: p.ID, Engine: p.Engine, PID: cmd.Process.Pid, StartedAt: time.Now().UTC()}
	m.log = nil
	m.addLogLocked("Engine process launched; service/network connectivity is NOT yet verified")
	go func() {
		waitErr := cmd.Wait()
		cause := context.Cause(ctx)
		policyFailure := managed.IsPolicyError(cause)
		cancel()
		if observedWait != nil {
			observedWait()
		}
		m.mu.Lock()
		// A signal can make Wait return before the signal call returns. Resolve
		// its actual dispatch result outside the mutex before classifying exit.
		// Recheck under the mutex: another stop attempt may have begun.
		for run.stopPending != nil {
			pending := run.stopPending
			m.mu.Unlock()
			<-pending
			m.mu.Lock()
		}
		result := RunResult{Reason: RunExited, WaitErr: waitErr}
		if policyFailure {
			result.Reason = RunPolicyRevoked
			result.PolicyErr = cause
		} else if run.stopAccepted {
			result.Reason = RunStopped
		} else if waitErr != nil {
			result.Reason = RunFailed
		}
		failed := result.Reason == RunFailed || result.Reason == RunPolicyRevoked
		terminalErr := errors.Join(result.PolicyErr, result.WaitErr)
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
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	cmd := m.cmd
	run := m.run
	m.mu.Unlock()
	if cmd == nil {
		return nil
	}
	signalErr := m.dispatchStop(cmd, run, func(process *os.Process) error {
		if err := interrupt(process); err != nil {
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
		_ = m.dispatchStop(cmd, run, kill)
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
	err := signal(cmd.Process)
	m.mu.Lock()
	if err == nil {
		run.stopAccepted = true
	}
	run.stopPending = nil
	if m.cmd == cmd && !run.stopAccepted {
		m.state.State = "running"
	}
	close(pending)
	m.mu.Unlock()
	return err
}
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	m.closing = true
	m.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- m.Stop() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Preview(p profile.Profile) (LaunchPlan, error) {
	return previewWithGuard(p, m.root, m.guard)
}
