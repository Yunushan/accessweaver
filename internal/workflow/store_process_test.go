package workflow

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

const workflowStoreSourceArgument = "--workflow-store-source-fixture-v1"

// These are cooperating, source-owned Managers and Go-test subprocesses. The
// platform override permits Preview only; every executor is an inert callback.
// No embedded Windows worker, product, service, vendor or network action runs.
func workflowStoreSourceManager(root string) *Manager {
	guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	m := NewWithGuard(root, guard)
	m.platform = "windows"
	m.requireAdmin = func() error { return errors.New("unexpected administrative fixture operation") }
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		return json.RawMessage(`{"ok":true}`), nil
	}
	return m
}

func TestWorkflowStoreProcessHelper(t *testing.T) {
	marker := -1
	for i, argument := range os.Args {
		if argument == "--" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	if len(os.Args[marker+1:]) != 2 || os.Args[marker+1] != workflowStoreSourceArgument {
		os.Exit(90)
	}
	os.Exit(workflowStoreSourceChild(os.Args[marker+2]))
}

func workflowStoreSourceChild(phase string) int {
	if phase != "admission" && phase != "execution" && phase != "terminal" {
		return 90
	}
	reader := bufio.NewReaderSize(os.Stdin, 4096)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 4096 {
		return 91
	}
	var request struct {
		Version int    `json:"version"`
		Root    string `json:"root"`
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.Version != 1 || !filepath.IsAbs(request.Root) {
		return 91
	}
	if decoder.Decode(new(any)) != io.EOF {
		return 91
	}
	root, err := os.Lstat(request.Root)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return 91
	}
	release := make(chan struct{})
	go func() {
		command, err := reader.ReadByte()
		if err != nil {
			os.Exit(98)
		}
		switch command {
		case 'q':
			close(release)
		case 'x':
			// Deliberately bypass all Manager/lease defers. The OS must release
			// the actual lock handles; no participant removes a lock file.
			os.Exit(97)
		default:
			os.Exit(98)
		}
	}()
	var ready sync.Once
	hold := func() {
		ready.Do(func() {
			if n, err := os.Stdout.Write([]byte{'r'}); err != nil || n != 1 {
				os.Exit(94)
			}
		})
		<-release
	}
	m := workflowStoreSourceManager(request.Root)
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		if phase == "execution" {
			hold()
		}
		return json.RawMessage(`{"ok":true}`), nil
	}
	m.persist = func(path string, data []byte) error {
		var job Job
		if json.Unmarshal(data, &job) != nil {
			return errors.New("source fixture record was invalid")
		}
		if phase == "admission" && job.State == "running" || phase == "terminal" && job.State != "running" {
			hold()
		}
		return profile.AtomicWrite(path, data)
	}
	plan, err := m.Preview(Request{Action: "discover"})
	if err != nil || !plan.Ready {
		return 92
	}
	started := make(chan error, 1)
	go func() { _, err := m.Start(plan.ID); started <- err }()
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	select {
	case err := <-started:
		if err != nil {
			return 93
		}
	case <-deadline.C:
		return 95
	}
	m.mu.Lock()
	done := m.done
	m.mu.Unlock()
	if done == nil {
		return 93
	}
	select {
	case <-done:
	case <-deadline.C:
		return 95
	}
	if job := m.Snapshot(); job.ID != plan.ID || job.State != "succeeded" || m.TerminalError(plan.ID) != nil {
		return 96
	}
	if n, err := os.Stdout.Write([]byte{'d'}); err != nil || n != 1 {
		return 94
	}
	return 0
}

type workflowStoreSourceOutput struct {
	mu      sync.Mutex
	events  chan byte
	count   int
	invalid bool
}

func (w *workflowStoreSourceOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, value := range data {
		if w.count >= 8 || value != 'r' && value != 'd' {
			w.invalid = true
			return 0, errors.New("source store protocol exceeded its fixed messages")
		}
		w.count++
		select {
		case w.events <- value:
		default:
			w.invalid = true
			return 0, errors.New("source store protocol queue exceeded its bound")
		}
	}
	return len(data), nil
}

func (w *workflowStoreSourceOutput) valid() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.invalid && w.count <= 2
}

type workflowStoreSourceStart struct {
	done chan struct{}
	job  Job
	err  error
}

type workflowStoreSourceFixture struct {
	t            *testing.T
	root         string
	identity     os.FileInfo
	preserve     bool
	cmd          *exec.Cmd
	input        io.WriteCloser
	output       *workflowStoreSourceOutput
	requested    bool
	waitStarted  bool
	waitDone     chan struct{}
	waitErr      error
	expectedExit int
	managers     []*Manager
	starts       []*workflowStoreSourceStart
}

func newWorkflowStoreSourceFixture(t *testing.T) *workflowStoreSourceFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-workflow-store-")
	if err != nil {
		t.Fatal("source store fixture root was unavailable")
	}
	identity, err := os.Lstat(root)
	if err != nil {
		t.Fatal("source store fixture identity was unavailable")
	}
	f := &workflowStoreSourceFixture{t: t, root: root, identity: identity}
	t.Cleanup(f.close)
	return f
}

func (f *workflowStoreSourceFixture) manager() (*Manager, *atomic.Int32) {
	m := workflowStoreSourceManager(f.root)
	calls := &atomic.Int32{}
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		calls.Add(1)
		return json.RawMessage(`{"ok":true}`), nil
	}
	f.managers = append(f.managers, m)
	return m, calls
}

func (f *workflowStoreSourceFixture) start(m *Manager, id string) *workflowStoreSourceStart {
	call := &workflowStoreSourceStart{done: make(chan struct{})}
	f.starts = append(f.starts, call)
	go func() { defer close(call.done); call.job, call.err = m.Start(id) }()
	return call
}

func (f *workflowStoreSourceFixture) awaitStart(call *workflowStoreSourceStart) {
	f.t.Helper()
	select {
	case <-call.done:
	case <-time.After(8 * time.Second):
		f.t.Fatal("source Manager admission did not return")
	}
}

func (f *workflowStoreSourceFixture) launch(phase string) {
	f.t.Helper()
	image, err := os.Executable()
	if err != nil {
		f.t.Fatal("source Go test image was unavailable")
	}
	f.output = &workflowStoreSourceOutput{events: make(chan byte, 8)}
	f.cmd = exec.Command(image, "-test.run=^TestWorkflowStoreProcessHelper$", "--", workflowStoreSourceArgument, phase)
	f.cmd.Stdout, f.cmd.Stderr = f.output, io.Discard
	f.input, err = f.cmd.StdinPipe()
	if err != nil {
		f.t.Fatal("source store request pipe was unavailable")
	}
	if f.cmd.Start() != nil {
		f.cmd = nil
		f.t.Fatal("source Go helper did not start")
	}
	request, err := json.Marshal(struct {
		Version int    `json:"version"`
		Root    string `json:"root"`
	}{1, f.root})
	if err != nil || len(request)+1 > 4096 {
		f.t.Fatal("source store bootstrap exceeded its fixed bound")
	}
	request = append(request, '\n')
	if n, err := f.input.Write(request); err != nil || n != len(request) {
		f.t.Fatal("source store bootstrap write failed")
	}
	select {
	case value := <-f.output.events:
		if value != 'r' {
			f.t.Fatal("source store readiness message was invalid")
		}
	case <-time.After(8 * time.Second):
		f.t.Fatal("source store helper did not reach its controlled phase")
	}
}

// Wait begins only after the release/crash decision. Any cleanup Kill occurs
// before this sole Wait, while the exact Go-owned child is still unreaped.
// No code signals the process once Wait has started, including timeout cleanup.
func (f *workflowStoreSourceFixture) finishChild(crash bool) bool {
	f.t.Helper()
	if f.cmd == nil {
		return true
	}
	if !f.waitStarted {
		if crash {
			f.expectedExit = 97
		}
		if !f.requested {
			command := byte('q')
			if crash {
				command = 'x'
			}
			f.requested = true
			if n, err := f.input.Write([]byte{command}); err != nil || n != 1 {
				f.t.Error("source store control write failed")
			}
		}
		if !crash {
			confirmed := false
			select {
			case value := <-f.output.events:
				confirmed = value == 'd'
			case <-time.After(8 * time.Second):
			}
			if !confirmed {
				f.t.Error("source store helper did not confirm Manager completion")
				if err := f.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					f.t.Error("unreaped source helper cleanup failed")
				}
			}
		}
		f.waitDone = make(chan struct{})
		f.waitStarted = true
		go func() { defer close(f.waitDone); f.waitErr = f.cmd.Wait() }()
	}
	select {
	case <-f.waitDone:
	case <-time.After(8 * time.Second):
		f.preserve = true
		f.t.Error("source helper Wait unconfirmed; fixture preserved")
		return false
	}
	if f.input != nil {
		if err := f.input.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			f.t.Error("source request pipe close failed")
		}
		f.input = nil
	}
	if f.expectedExit == 0 {
		if f.waitErr != nil {
			f.t.Error("source helper did not exit successfully")
			return false
		}
	} else {
		var exited *exec.ExitError
		if !errors.As(f.waitErr, &exited) || exited.ExitCode() != f.expectedExit {
			f.t.Error("source helper did not perform the intentional fixed-code crash")
			return false
		}
	}
	if !f.output.valid() {
		f.t.Error("source helper exceeded its bounded protocol")
		return false
	}
	return true
}

func (f *workflowStoreSourceFixture) close() {
	if f.cmd != nil {
		f.finishChild(f.expectedExit != 0)
	} else if f.input != nil {
		_ = f.input.Close()
	}
	for _, call := range f.starts {
		select {
		case <-call.done:
		case <-time.After(8 * time.Second):
			f.preserve = true
			f.t.Error("source Manager admission remains pending; fixture preserved")
		}
	}
	for _, manager := range f.managers {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		err := manager.Shutdown(ctx)
		cancel()
		if err != nil {
			f.preserve = true
			f.t.Error("source Manager cleanup remains uncertain; fixture preserved")
		}
	}
	if f.preserve {
		return
	}
	named, err := os.Lstat(f.root)
	if err != nil || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(named, f.identity) {
		f.t.Error("changed source store fixture root was preserved")
		return
	}
	// Only this captured fresh test root is removed, after every accepted child
	// and Manager has joined. Production never removes persistent lock files.
	if err := os.RemoveAll(f.root); err != nil {
		f.t.Error("owned source store fixture cleanup failed")
	}
}

func workflowStoreAwaitDone(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	done := m.done
	m.mu.Unlock()
	if done == nil {
		t.Fatal("source Manager did not publish its reservation")
	}
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("source Manager did not finish persistence and lease cleanup")
	}
}

func workflowStoreLockIdentities(t *testing.T, root string) map[string]os.FileInfo {
	t.Helper()
	identities := make(map[string]os.FileInfo)
	for _, name := range []string{".workflow-active.lock", ".workflow-store.lock"} {
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("persistent workflow coordination file was unavailable")
		}
		identities[name] = info
	}
	return identities
}

func workflowStoreSameLocks(t *testing.T, root string, identities map[string]os.FileInfo) {
	t.Helper()
	for name, identity := range identities {
		current, err := os.Lstat(filepath.Join(root, name))
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(identity, current) {
			t.Fatal("workflow lease release removed or replaced its persistent file")
		}
	}
}

func workflowStoreReviewedPlan(t *testing.T, m *Manager) Plan {
	t.Helper()
	plan, err := m.Preview(Request{Action: "discover"})
	if err != nil || !plan.Ready {
		t.Fatal("inert source workflow could not be reviewed")
	}
	return plan
}

func workflowStoreAssertBusy(t *testing.T, f *workflowStoreSourceFixture, m *Manager, calls *atomic.Int32, plan Plan) {
	t.Helper()
	attempt := f.start(m, plan.ID)
	f.awaitStart(attempt)
	if !errors.Is(attempt.err, ErrWorkflowAdmission) || !errors.Is(attempt.err, ErrWorkflowStore) || !errors.Is(attempt.err, ErrWorkflowBusy) || !errors.Is(attempt.err, filelock.ErrBusy) {
		t.Fatal("another Manager bypassed the shared active workflow lease")
	}
	if calls.Load() != 0 {
		t.Fatal("contended workflow reached its executor")
	}
	if _, err := os.Lstat(filepath.Join(m.root, plan.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("contended workflow created a durable record")
	}
	if _, err := os.Lstat(filepath.Join(m.root, plan.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("contended workflow created a work directory")
	}
}

func TestWorkflowStoreProcessLeaseCoversAdmissionExecutionAndTerminalPersistence(t *testing.T) {
	for _, phase := range []string{"admission", "execution", "terminal"} {
		t.Run(phase, func(t *testing.T) {
			f := newWorkflowStoreSourceFixture(t)
			f.launch(phase)
			identities := workflowStoreLockIdentities(t, f.root)
			store, err := filelock.TryAcquire(filepath.Join(f.root, ".workflow-store.lock"))
			if phase == "execution" {
				if err != nil || store == nil {
					t.Fatal("record transaction lease remained held throughout inert execution")
				}
				if store.Close() != nil {
					t.Fatal("source transaction probe did not close")
				}
			} else if !errors.Is(err, filelock.ErrBusy) || store != nil {
				if store != nil {
					_ = store.Close()
				}
				t.Fatal("record persistence was outside the shared transaction lease")
			}
			m, calls := f.manager()
			plan := workflowStoreReviewedPlan(t, m)
			workflowStoreAssertBusy(t, f, m, calls, plan)
			if !f.finishChild(false) {
				t.Fatal("source owner did not drain before replacement admission")
			}
			workflowStoreSameLocks(t, f.root, identities)
			// Contention does not consume the already reviewed unexpired plan.
			retry := f.start(m, plan.ID)
			f.awaitStart(retry)
			if retry.err != nil || retry.job.ID != plan.ID {
				t.Fatal("reviewed workflow could not start after actual owner release")
			}
			workflowStoreAwaitDone(t, m)
			if calls.Load() != 1 || m.Snapshot().State != "succeeded" || m.TerminalError(plan.ID) != nil {
				t.Fatal("subsequent source workflow did not finish exactly once")
			}
			workflowStoreSameLocks(t, f.root, identities)
		})
	}
}

func TestWorkflowStoreProcessCrashReleasesHandlesWithoutDeletingLocks(t *testing.T) {
	f := newWorkflowStoreSourceFixture(t)
	f.launch("execution")
	identities := workflowStoreLockIdentities(t, f.root)
	entries, err := os.ReadDir(filepath.Join(f.root, "workflows"))
	if err != nil || len(entries) != 1 || entries[0].IsDir() || filepath.Ext(entries[0].Name()) != ".json" {
		t.Fatal("source crash fixture had no unique durable running record")
	}
	oldPath := filepath.Join(f.root, "workflows", entries[0].Name())
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal("source crash evidence could not be captured")
	}
	m, calls := f.manager()
	plan := workflowStoreReviewedPlan(t, m)
	workflowStoreAssertBusy(t, f, m, calls, plan)
	if !f.finishChild(true) {
		t.Fatal("source intentional crash did not join")
	}
	workflowStoreSameLocks(t, f.root, identities)
	retry := f.start(m, plan.ID)
	f.awaitStart(retry)
	// The OS released the exact persistent locks, but an interrupted new
	// lifecycle intent is not evidence of confirmed local completion.
	if !errors.Is(retry.err, ErrWorkflowLifecyclePending) || !errors.Is(retry.err, ErrWorkflowAdmission) {
		t.Fatal("unacknowledged crash intent did not refuse subsequent admission")
	}
	workflowStoreAwaitDone(t, m)
	if calls.Load() != 0 {
		t.Fatal("post-crash review-required admission executed")
	}
	lease, err := openWorkflowStoreLease(filepath.Join(f.root, workflowActiveLockName))
	if err != nil {
		t.Fatal("actual OS crash release was not independently observable")
	}
	if err := lease.Close(); err != nil {
		t.Fatal("crash-release probe did not close")
	}
	if _, err := m.History(); err != nil {
		t.Fatal("interrupted source history became unavailable")
	}
	if _, err := m.CaptureHistoryInventory(context.Background()); err != nil {
		t.Fatal("interrupted source inventory became unavailable")
	}
	retained, err := os.ReadFile(oldPath)
	if err != nil || !bytes.Equal(retained, oldBytes) {
		t.Fatal("crash recovery admission rewrote the interrupted record")
	}
	workflowStoreSameLocks(t, f.root, identities)
}

func TestWorkflowStoreHistoryReadsNeverCreateRootsOrLockFiles(t *testing.T) {
	for _, kind := range []string{"missing-config", "existing-config", "existing-workflows"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "config")
			if kind != "missing-config" {
				if os.Mkdir(root, 0700) != nil {
					t.Fatal("source empty config fixture was unavailable")
				}
			}
			if kind == "existing-workflows" {
				if os.Mkdir(filepath.Join(root, "workflows"), 0700) != nil {
					t.Fatal("source empty history fixture was unavailable")
				}
			}
			m := workflowStoreSourceManager(root)
			history, err := m.HistoryContext(context.Background())
			if err != nil || len(history) != 0 {
				t.Fatal("empty source history was not readable")
			}
			for _, name := range []string{".workflow-active.lock", ".workflow-store.lock"} {
				if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("read-only history created a coordination file")
				}
			}
			if kind == "missing-config" {
				if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("read-only history created its missing config parent")
				}
			}
		})
	}
}

func TestWorkflowStorePersistentLocksDoNotConsumeHistoryEntryBudget(t *testing.T) {
	f := newWorkflowStoreSourceFixture(t)
	m, calls := f.manager()
	plan := workflowStoreReviewedPlan(t, m)
	started := f.start(m, plan.ID)
	f.awaitStart(started)
	if started.err != nil {
		t.Fatal("source workflow admission failed")
	}
	workflowStoreAwaitDone(t, m)
	workflowStoreLockIdentities(t, f.root)
	info, err := os.Stat(filepath.Join(m.root, plan.ID+".json"))
	if err != nil {
		t.Fatal("source history record was unavailable")
	}
	history, err := m.history(1, info.Size())
	if err != nil || len(history) != 1 || history[0].ID != plan.ID || calls.Load() != 1 {
		t.Fatal("config-root coordination files consumed the history record budget")
	}
	entries, err := os.ReadDir(m.root)
	if err != nil || len(entries) != 1 {
		t.Fatal("coordination files were placed inside the history directory")
	}
}
