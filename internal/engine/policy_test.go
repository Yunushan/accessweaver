package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func enginePolicy(t *testing.T, p managed.Policy) *managed.Authority {
	t.Helper()
	now := time.Now().UTC()
	p.SchemaVersion = 1
	p.Revision = 1
	p.IssuedAt = now.Add(-time.Minute)
	p.ExpiresAt = now.Add(time.Hour)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := private.Public().(ed25519.PublicKey)
	envelope, err := managed.Sign(data, private, now)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := managed.PrepareInstallation(envelope, public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := managed.DecodeInstallation(installation, now)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func TestDeniedLaunchDoesNotMaterializeInputsOrStartProcess(t *testing.T) {
	root := t.TempDir()
	p := profile.New("denied-launch", "Denied", "byedpi")
	p.Binary = fixtureBinary(t, root, "ciadpi")
	p.Routing.IncludeDomains = []string{"example.org"}
	denied := enginePolicy(t, managed.Policy{})
	manager := NewManagerWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return denied, nil }))
	plan, err := manager.Preview(p)
	if err != nil || plan.Ready || !strings.Contains(strings.Join(plan.Issues, ";"), "administrator policy") {
		t.Fatal("preview ignored machine policy", err)
	}
	if err := manager.Start(p); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("denied engine start did not preserve policy error", err)
	}
	if _, err := os.Stat(filepath.Join(root, "generated")); !os.IsNotExist(err) {
		t.Fatal("denied start wrote generated inputs", err)
	}
	if state := manager.Snapshot(); state.PID != 0 || state.State != "stopped" {
		t.Fatal("denied start changed running state", state)
	}
}

func TestEnginePolicyRecheckedImmediatelyBeforeStart(t *testing.T) {
	root := t.TempDir()
	p := profile.New("revoked-launch", "Revoked", "byedpi")
	p.Binary = fixtureBinary(t, root, "ciadpi")
	denied := enginePolicy(t, managed.Policy{})
	reads := 0
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		reads++
		if reads == 1 {
			return nil, nil
		}
		return denied, nil
	})
	manager := NewManagerWithGuard(root, guard)
	if err := manager.Start(p); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("launch did not observe policy installed after preview", err)
	}
	if reads < 2 || manager.Snapshot().PID != 0 {
		t.Fatal("engine execution bypassed policy recheck")
	}
}

func TestShutdownPreventsLateStartAfterAuthorizationWait(t *testing.T) {
	root := t.TempDir()
	p := profile.New("closing-launch", "Closing", "byedpi")
	p.Binary = fixtureBinary(t, root, "ciadpi")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	guard := managed.NewGuard(func() (*managed.Authority, error) { once.Do(func() { close(entered); <-release }); return nil, nil })
	manager := NewManagerWithGuard(root, guard)
	started := make(chan error, 1)
	go func() { started <- manager.Start(p) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("start did not reach authority")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatal("shutdown did not report pending start", err)
	}
	close(release)
	select {
	case err := <-started:
		if err == nil || !strings.Contains(err.Error(), "shutting down") {
			t.Fatal("closing manager permitted a late launch", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending start did not finish")
	}
	if manager.Snapshot().PID != 0 {
		t.Fatal("shutdown left a late child")
	}
}

func TestRunningEngineStopsAfterEnrollmentOrSourceFailure(t *testing.T) {
	for _, sourceFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(sourceFailure), func(t *testing.T) {
			root := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			name := "ciadpi"
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			binary := filepath.Join(root, name)
			if err := os.WriteFile(binary, contents, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("ACCESSWEAVER_FIXTURE", "1")
			t.Setenv("ACCESSWEAVER_FIXTURE_RECORD", filepath.Join(root, "record.json"))
			denied := enginePolicy(t, managed.Policy{})
			var changed atomic.Bool
			guard := managed.NewGuard(func() (*managed.Authority, error) {
				if changed.Load() {
					if sourceFailure {
						return nil, managed.ErrUnavailable
					}
					return denied, nil
				}
				return nil, nil
			})
			manager := NewManagerWithGuard(root, guard)
			t.Cleanup(func() { _ = manager.Stop() })
			p := profile.New("active-revocation", "Active revocation", "byedpi")
			p.Binary = binary
			if err := manager.Start(p); err != nil {
				t.Fatal(err)
			}
			if manager.Snapshot().PID == 0 {
				t.Fatal("fixture never started")
			}
			changed.Store(true)
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) && manager.Snapshot().PID != 0 {
				time.Sleep(10 * time.Millisecond)
			}
			state := manager.Snapshot()
			if state.PID != 0 || state.State != "error" || (!strings.Contains(state.LastError, "machine policy changed") && !strings.Contains(state.LastError, "policy is unavailable")) {
				t.Fatalf("active revocation lost child or policy outcome: %+v", state)
			}
			// Starting again requires fresh approval. A terminated monitor must
			// not cancel a later generation after explicit administrator repair.
			changed.Store(false)
			if err := manager.Start(p); err != nil {
				t.Fatal(err)
			}
			if err := manager.Stop(); err != nil {
				t.Fatal(err)
			}
			if state := manager.Snapshot(); state.PID != 0 || state.LastError != "" {
				t.Fatal(state)
			}
		})
	}
}
