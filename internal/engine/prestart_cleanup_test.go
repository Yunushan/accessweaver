package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPreStartOwnerCleanupAndRetainedFault(t *testing.T) {
	for _, phase := range []string{"partial-factory", "canceled", "missing-executable"} {
		for _, uncertain := range []bool{false, true} {
			label := "clean"
			if uncertain {
				label = "uncertain"
			}
			t.Run(phase+"/"+label, func(t *testing.T) {
				f := newAtomicWriteGeneratedFixture(t)
				f.profile.Routing.IncludeDomains = nil
				f.profile.Routing.ExcludeDomains = nil
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				manager := NewManagerWithGuard(f.root, f.guard)
				primary := errors.New("PRIVATE_FACTORY_CAUSE")
				closeCause := &os.PathError{Op: "PRIVATE_CLOSE", Path: "PRIVATE_RESOURCE_PATH", Err: errors.New("PRIVATE_CLOSE_CAUSE")}
				attempts := 0
				var owner *preparationLifetimeTap
				manager.prepareLifetime = func(cmd *exec.Cmd) (processLifetime, error) {
					attempts++
					native, err := prepareProcessLifetime(cmd)
					if err != nil {
						return nil, err
					}
					owner = &preparationLifetimeTap{processLifetime: native}
					if uncertain {
						owner.closeCause = closeCause
					}
					switch phase {
					case "partial-factory":
						return owner, primary
					case "canceled":
						cancel()
					case "missing-executable":
						if err := os.Remove(f.profile.Binary); err != nil {
							return owner, err
						}
					}
					return owner, nil
				}
				run, err := manager.StartTrackedContext(ctx, f.profile)
				if run != nil || err == nil || owner == nil || owner.aborted != 1 || attempts != 1 {
					t.Fatal("pre-start owner or error lost")
				}
				switch phase {
				case "partial-factory":
					if !errors.Is(err, primary) {
						t.Fatal("partial factory cause lost")
					}
				case "canceled":
					if !errors.Is(err, context.Canceled) {
						t.Fatal("caller cancellation cause lost")
					}
				case "missing-executable":
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatal("actual native start refusal cause lost")
					}
				}
				state := manager.Snapshot()
				if state.PID != 0 || state.LifecyclePending || manager.run != nil || manager.cmd != nil {
					t.Fatal("pre-start failure invented a live child")
				}
				if !uncertain {
					if errors.Is(err, ErrPreparationCleanupUncertain) || state.State != "stopped" || state.LastError != "" {
						t.Fatal("confirmed cleanup became sticky")
					}
					refusal := errors.New("source refuses another owner")
					manager.prepareLifetime = func(*exec.Cmd) (processLifetime, error) { attempts++; return nil, refusal }
					if phase != "missing-executable" {
						next, e := manager.StartTracked(f.profile)
						if next != nil || !errors.Is(e, refusal) || attempts != 2 {
							t.Fatal("clean pre-start failure blocked later admission")
						}
					}
					return
				}
				if !errors.Is(err, ErrPreparationCleanupUncertain) || err.Error() != ErrPreparationCleanupUncertain.Error() || !errors.Is(err, closeCause) {
					t.Fatal("cleanup uncertainty lost cause or exposed private details")
				}
				if state.State != "error" || state.LastError != ErrPreparationCleanupUncertain.Error() {
					t.Fatal("cleanup uncertainty absent from runtime")
				}
				for _, context := range []context.Context{context.Background(), ctx} {
					next, e := manager.StartTrackedContext(context, f.profile)
					if next != nil || !errors.Is(e, ErrPreparationCleanupUncertain) || attempts != 1 || owner.aborted != 1 {
						t.Fatal("unconfirmed owner was retried or replaced")
					}
				}
				if e := manager.Stop(); !errors.Is(e, ErrPreparationCleanupUncertain) || owner.aborted != 1 {
					t.Fatal("Stop hid uncertainty or retried unknown close")
				}
				if e := manager.RetryCleanup(&Run{}); !errors.Is(e, ErrRunUnavailable) || owner.aborted != 1 {
					t.Fatal("a missing child authorized a numeric-handle retry")
				}
				shutdown, cancelShutdown := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancelShutdown()
				if e := manager.Shutdown(shutdown); !errors.Is(e, ErrPreparationCleanupUncertain) || attempts != 1 || owner.aborted != 1 {
					t.Fatal("no-child shutdown hid cleanup uncertainty")
				}
				canceled, cancelAgain := context.WithCancel(context.Background())
				cancelAgain()
				if e := manager.Shutdown(canceled); !errors.Is(e, ErrPreparationCleanupUncertain) {
					t.Fatal("published shutdown fault lost to canceled waiter")
				}
			})
		}
	}
}

func TestPreStartFactoryErrorMarkerAndNilOwner(t *testing.T) {
	for _, marked := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil-owner", true: "factory-cleanup-failure"}[marked], func(t *testing.T) {
			f := newAtomicWriteGeneratedFixture(t)
			f.profile.Routing.IncludeDomains = nil
			f.profile.Routing.ExcludeDomains = nil
			manager := NewManagerWithGuard(f.root, f.guard)
			attempts := 0
			cause := errors.New("PRIVATE_INITIALIZER_CAUSE")
			reported := preparationCleanupFailure(ErrProcessLifecycle, cause, &struct{ owned bool }{true})
			manager.prepareLifetime = func(*exec.Cmd) (processLifetime, error) {
				attempts++
				if marked {
					return nil, reported
				}
				return nil, nil
			}
			run, err := manager.StartTracked(f.profile)
			if run != nil || err == nil || attempts != 1 || manager.Snapshot().PID != 0 {
				t.Fatal("invalid factory result admitted a process")
			}
			if marked {
				if !errors.Is(err, cause) || !errors.Is(err, ErrPreparationCleanupUncertain) {
					t.Fatal("initializer cleanup marker lost")
				}
				if next, e := manager.StartTracked(f.profile); next != nil || !errors.Is(e, ErrPreparationCleanupUncertain) || attempts != 1 {
					t.Fatal("initializer cleanup failure did not close admission")
				}
			} else if !errors.Is(err, ErrProcessLifecycle) || manager.Snapshot().State != "stopped" {
				t.Fatal("missing owner was treated as successful preparation")
			}
		})
	}
}
