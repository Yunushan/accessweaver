package engine

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
)

type preparationOwnedReader struct {
	*configOwnedReader
	afterClose   func()
	closeEntered chan struct{}
	releaseClose <-chan struct{}
}

func (r *preparationOwnedReader) Close() error {
	if r.closeEntered != nil {
		close(r.closeEntered)
		<-r.releaseClose
	}
	err := r.configOwnedReader.Close()
	if r.afterClose != nil {
		r.afterClose()
	}
	return err
}

func TestPreparationContextReadersPreserveCancellationAndClose(t *testing.T) {
	for _, kind := range []string{"configuration", "executable-hash"} {
		for _, phase := range []string{"before-read", "after-read", "after-close"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				readCause := errors.New("PRIVATE_READ_CAUSE")
				closeCause := &os.PathError{Op: "PRIVATE_CLOSE", Path: "PRIVATE_CONFIGURATION_PATH", Err: errors.New("PRIVATE_CLOSE_CAUSE")}
				r := &preparationOwnedReader{configOwnedReader: &configOwnedReader{hashOwnedReader: newHashOwnedReader(t)}}
				r.closeCause = closeCause
				switch phase {
				case "before-read":
					cancel()
				case "after-read":
					r.readCause = readCause
					r.afterRead = cancel
				case "after-close":
					r.afterClose = cancel
				}
				var err error
				if kind == "configuration" {
					var data []byte
					data, err = readOwnedConfigInputContext(ctx, r)
					if data != nil {
						t.Fatal("canceled configuration bytes released")
					}
				} else {
					var digest string
					digest, err = executableHashContext(ctx, r)
					if digest != "" {
						t.Fatal("canceled digest released")
					}
				}
				var original *os.PathError
				if !errors.Is(err, context.Canceled) || !errors.As(err, &original) || original != closeCause {
					t.Fatal("cancellation or original Close cofailure lost")
				}
				if phase == "after-read" && !errors.Is(err, readCause) {
					t.Fatal("original read cofailure lost")
				}
				if r.closes != 1 || r.actualClose != nil {
					t.Fatal("actual reader Close not confirmed once")
				}
				if phase == "before-read" && (r.reads != 0 || r.stats != 0) {
					t.Fatal("canceled reader entered body I/O")
				}
				if n, e := r.file.Read(make([]byte, 1)); n != 0 || !errors.Is(e, os.ErrClosed) {
					t.Fatal("reader remained open")
				}
				if err.Error() != errConfigInputUnavailable.Error() && err.Error() != errExecutableHashUnavailable.Error() {
					t.Fatal("private completion details escaped")
				}
			})
		}
	}
}

func TestPreparationContextWaitsForOwnedClose(t *testing.T) {
	for _, kind := range []string{"configuration", "executable-hash"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type completion struct {
				err      error
				released bool
			}
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan completion, 1)
			r := &preparationOwnedReader{configOwnedReader: &configOwnedReader{hashOwnedReader: newHashOwnedReader(t)}, closeEntered: entered, releaseClose: release}
			var once sync.Once
			joined := false
			t.Cleanup(func() {
				once.Do(func() { close(release) })
				if !joined {
					<-done
				}
			})
			go func() {
				if kind == "configuration" {
					data, err := readOwnedConfigInputContext(ctx, r)
					done <- completion{err: err, released: data != nil}
				} else {
					digest, err := executableHashContext(ctx, r)
					done <- completion{err: err, released: digest != ""}
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("reader never entered Close")
			}
			cancel()
			select {
			case <-done:
				joined = true
				t.Fatal("cancellation abandoned actual owned Close")
			default:
			}
			once.Do(func() { close(release) })
			result := <-done
			joined = true
			if result.released || !errors.Is(result.err, context.Canceled) || r.closes != 1 || r.actualClose != nil {
				t.Fatal("joined cancellation/Close completion lost")
			}
		})
	}
}

// Observe evaluation of the actual lock select's Done operand, while forwarding
// the unchanged cancellation channel and every other context method.
type preparationAdmissionContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *preparationAdmissionContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestPreparationContextCanceledAdmissionDoesNotWaitOrPrepare(t *testing.T) {
	f := newAtomicWriteGeneratedFixture(t)
	f.previewBeforeObstruction(t)
	manager := NewManagerWithGuard(f.root, f.guard)
	owners := 0
	manager.prepareLifetime = func(*exec.Cmd) (processLifetime, error) {
		owners++
		return nil, errors.New("source refuses process ownership")
	}
	manager.opMu.Lock()
	locked := true
	defer func() {
		if locked {
			manager.opMu.Unlock()
		}
	}()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &preparationAdmissionContext{Context: base, waiting: make(chan struct{})}
	type admission struct {
		run *Run
		err error
	}
	done := make(chan admission, 1)
	go func() { run, err := manager.StartTrackedContext(ctx, f.profile); done <- admission{run: run, err: err} }()
	select {
	case <-ctx.waiting:
	case <-time.After(3 * time.Second):
		cancel()
		manager.opMu.Unlock()
		locked = false
		<-done
		t.Fatal("launch never reached cancelable lock wait")
	}
	cancel()
	select {
	case result := <-done:
		if result.run != nil || !errors.Is(result.err, context.Canceled) || owners != 0 {
			t.Fatal("canceled launch admission lost its cause or reached ownership")
		}
	case <-time.After(3 * time.Second):
		manager.opMu.Unlock()
		locked = false
		<-done
		t.Fatal("canceled launch waited for operation lock")
	}
	if _, err := os.Lstat(filepath.Join(f.root, "generated")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled admission wrote generated inputs")
	}
	manager.opMu.Unlock()
	locked = false
	if err := manager.opMu.LockContext(context.Background()); err != nil {
		t.Fatal("canceled waiter consumed operation token")
	}
	manager.opMu.Unlock()
}

func TestPreparationContextCancellationBeforeGeneratedWrites(t *testing.T) {
	f := newAtomicWriteGeneratedFixture(t)
	f.previewBeforeObstruction(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := managed.NewGuard(func() (*managed.Authority, error) { cancel(); return nil, nil })
	manager := NewManagerWithGuard(f.root, guard)
	owners := 0
	manager.prepareLifetime = func(*exec.Cmd) (processLifetime, error) {
		owners++
		return nil, errors.New("source refuses process ownership")
	}
	run, err := manager.StartTrackedContext(ctx, f.profile)
	if run != nil || !errors.Is(err, context.Canceled) || owners != 0 {
		t.Fatal("canceled preparation reached process ownership")
	}
	if _, err := os.Lstat(filepath.Join(f.root, "generated")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled preparation wrote generated inputs")
	}
	if state := manager.Snapshot(); state.State != "stopped" || state.PID != 0 || state.LifecyclePending {
		t.Fatal("canceled preparation changed runtime state")
	}
}

type preparationLifetimeTap struct {
	processLifetime
	aborted    int
	closeCause error
}

func (o *preparationLifetimeTap) abortStart() error {
	o.aborted++
	err := o.processLifetime.abortStart()
	if err != nil {
		return err
	}
	return o.closeCause
}

func TestPreparationContextCancellationAfterOwnerAllocationClosesOwner(t *testing.T) {
	f := newAtomicWriteGeneratedFixture(t)
	f.profile.Routing.IncludeDomains = nil
	f.profile.Routing.ExcludeDomains = nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := NewManagerWithGuard(f.root, f.guard)
	closeCause := errors.New("PRIVATE_OWNER_CLOSE_CAUSE")
	var tap *preparationLifetimeTap
	manager.prepareLifetime = func(cmd *exec.Cmd) (processLifetime, error) {
		owner, err := prepareProcessLifetime(cmd)
		if err != nil {
			return nil, err
		}
		tap = &preparationLifetimeTap{processLifetime: owner, closeCause: closeCause}
		cancel()
		return tap, nil
	}
	run, err := manager.StartTrackedContext(ctx, f.profile)
	if run != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, closeCause) || tap == nil || tap.aborted != 1 || !errors.Is(err, ErrPreparationCleanupUncertain) || err.Error() != ErrPreparationCleanupUncertain.Error() {
		t.Fatal("canceled pre-start owner was not closed or cofailure lost")
	}
	if manager.Snapshot().PID != 0 {
		t.Fatal("canceled owner allocation started a child")
	}
}

func TestPreparationContextAcceptedRunSurvivesCallerCancellation(t *testing.T) {
	p, root := trackedFixture(t)
	guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	manager := NewManagerWithGuard(root, guard)
	manager.output = io.Discard
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.afterStart = cancel
	t.Cleanup(func() { _ = manager.Stop() })
	run, err := manager.StartTrackedContext(ctx, p)
	if err != nil || run == nil || ctx.Err() != context.Canceled {
		t.Fatal("accepted real launch was lost to caller cancellation")
	}
	waitTrackedReady(t)
	select {
	case <-run.Done():
		t.Fatal("caller cancellation terminated accepted child")
	default:
	}
	if err := manager.Stop(); err != nil {
		t.Fatal("owned accepted launch stop failed")
	}
	result := waitTracked(t, run)
	if result.Reason != RunStopped || result.PolicyErr != nil || result.LifecycleErr != nil {
		t.Fatal("accepted child lost its managed lifetime")
	}
}
