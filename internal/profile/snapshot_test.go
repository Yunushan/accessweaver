package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Yunushan/accessweaver/internal/managed"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func snapshotFixture() []Profile {
	p := New("saved-profile", "Saved profile", "byedpi")
	p.UpdatedAt = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	return []Profile{p}
}
func TestSnapshotRestoreRoundTripAndNoReseeding(t *testing.T) {
	for _, profiles := range [][]Profile{snapshotFixture(), {}} {
		root := filepath.Join(t.TempDir(), "restored")
		if err := RestoreSnapshot(context.Background(), root, profiles, false, managed.NewGuard(nil)); err != nil {
			t.Fatal(err)
		}
		store, err := NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Seed(Builtins()); err != nil {
			t.Fatal(err)
		}
		got, err := store.SnapshotContext(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, profiles) {
			t.Fatalf("restore changed saved revisions/content: %#v %#v", got, profiles)
		}
		if err := RestoreSnapshot(context.Background(), root, profiles, false, managed.NewGuard(nil)); err == nil {
			t.Fatal("existing root replaced")
		}
	}
}
func TestRestoreMarkerBlocksAllOrdinaryStoreAccess(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := snapshotFixture()[0]
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Root, restoreMarker), []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	checks := []error{store.Save(p), store.SaveIfUnchanged(p), store.Delete(p.ID), store.DeleteIfUnchanged(p.ID, p.UpdatedAt), store.Seed(Builtins())}
	_, err = store.Get(p.ID)
	checks = append(checks, err)
	_, err = store.List()
	checks = append(checks, err)
	_, err = store.SnapshotContext(context.Background())
	checks = append(checks, err)
	_, err = NewStore(store.Root)
	checks = append(checks, err)
	for _, err := range checks {
		if !errors.Is(err, ErrRestoreIncomplete) {
			t.Fatal("incomplete restore exposed data", err)
		}
	}
}
func prepareInterruptedSnapshot(t *testing.T, root string, profiles []Profile, published bool) {
	t.Helper()
	files, marker, err := restoreFiles(profiles)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeRestoreFile(filepath.Join(root, restoreMarker), marker); err != nil {
		t.Fatal(err)
	}
	name := restoreStage
	if published {
		name = "profiles"
	}
	if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
		t.Fatal(err)
	}
	for file, data := range files {
		if !published {
			data = []byte("partial unsynced candidate")
		}
		if err := writeRestoreFile(filepath.Join(root, name, file), data); err != nil {
			t.Fatal(err)
		}
	}
}
func TestInterruptedRestoreResumesBeforeAndAfterPublication(t *testing.T) {
	profiles := snapshotFixture()
	for _, published := range []bool{false, true} {
		root := filepath.Join(t.TempDir(), "restored")
		prepareInterruptedSnapshot(t, root, profiles, published)
		if _, err := NewStore(root); !errors.Is(err, ErrRestoreIncomplete) {
			t.Fatal(err)
		}
		if err := RestoreSnapshot(context.Background(), root, profiles, true, managed.NewGuard(nil)); err != nil {
			t.Fatal(err)
		}
		store, err := NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.SnapshotContext(context.Background())
		if err != nil || !reflect.DeepEqual(got, profiles) {
			t.Fatal(got, err)
		}
	}
}
func TestRestorePreservesUnexpectedDataAndRejectsWrongResume(t *testing.T) {
	profiles := snapshotFixture()
	root := filepath.Join(t.TempDir(), "restored")
	prepareInterruptedSnapshot(t, root, profiles, false)
	wrong := snapshotFixture()
	wrong[0].Name = "Different"
	if err := RestoreSnapshot(context.Background(), root, wrong, true, managed.NewGuard(nil)); err == nil {
		t.Fatal("unrelated snapshot resumed")
	}
	extra := filepath.Join(root, restoreStage, "unrelated.txt")
	if err := os.WriteFile(extra, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSnapshot(context.Background(), root, profiles, true, managed.NewGuard(nil)); err == nil {
		t.Fatal("unexpected staging file ignored")
	}
	if data, err := os.ReadFile(extra); err != nil || string(data) != "keep" {
		t.Fatal("unrelated data changed", err)
	}
	if _, err := NewStore(root); !errors.Is(err, ErrRestoreIncomplete) {
		t.Fatal("failed restore became usable", err)
	}
}
func TestPolicyRevocationLeavesRestoreBlockedAndResumable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "restored")
	reads := 0
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		reads++
		if reads >= 3 {
			return nil, managed.ErrUnavailable
		}
		return nil, nil
	})
	if err := RestoreSnapshot(context.Background(), root, snapshotFixture(), false, guard); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := NewStore(root); !errors.Is(err, ErrRestoreIncomplete) {
		t.Fatal(err)
	}
	if err := RestoreSnapshot(context.Background(), root, snapshotFixture(), true, managed.NewGuard(nil)); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRestoreCrashHelper(t *testing.T) {
	mode := os.Getenv("ACCESSWEAVER_RESTORE_CRASH_HELPER")
	if mode != "staging" && mode != "published" {
		return
	}
	reads := 0
	stopAt := 3
	if mode == "published" {
		stopAt = 5
	}
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		reads++
		if reads == stopAt {
			os.Exit(79)
		}
		return nil, nil
	})
	err := RestoreSnapshot(context.Background(), os.Getenv("ACCESSWEAVER_RESTORE_CRASH_ROOT"), snapshotFixture(), false, guard)
	t.Fatal("crash helper returned unexpectedly", err)
}
func TestNativeProcessExitRestoreResume(t *testing.T) {
	for _, mode := range []string{"staging", "published"} {
		t.Run(mode, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recovered")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeRestoreCrashHelper$")
			cmd.Env = append(os.Environ(), "ACCESSWEAVER_RESTORE_CRASH_HELPER="+mode, "ACCESSWEAVER_RESTORE_CRASH_ROOT="+root)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 79 {
				t.Fatalf("helper did not exit at requested mutation: %s %v", output, err)
			}
			if _, err := NewStore(root); !errors.Is(err, ErrRestoreIncomplete) {
				t.Fatal("abandoned state exposed", err)
			}
			stage := restoreStage
			if mode == "published" {
				stage = "profiles"
			}
			if _, err := os.Stat(filepath.Join(root, stage)); err != nil {
				t.Fatal("helper did not reach stage", err)
			}
			if err := RestoreSnapshot(ctx, root, snapshotFixture(), true, managed.NewGuard(nil)); err != nil {
				t.Fatal("OS did not release restore locks or resume failed", err)
			}
			store, err := NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			got, err := store.SnapshotContext(ctx)
			if err != nil || !reflect.DeepEqual(got, snapshotFixture()) {
				t.Fatal(got, err)
			}
		})
	}
}
func TestRestoreRejectsStagingSymlinkWithoutFollowing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recovered")
	profiles := snapshotFixture()
	prepareInterruptedSnapshot(t, root, profiles, false)
	staged := filepath.Join(root, restoreStage, profiles[0].ID+".json")
	outside := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(outside, []byte("preserve unrelated bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, staged); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "privilege") {
			t.Skip("symlink creation unavailable")
		}
		t.Fatal(err)
	}
	if err := RestoreSnapshot(context.Background(), root, profiles, true, managed.NewGuard(nil)); err == nil {
		t.Fatal("staging symlink accepted")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "preserve unrelated bytes" {
		t.Fatal("symlink target changed", err)
	}
}

func TestSnapshotRejectsProfileThatWouldExceedRestoreDecodeLimit(t *testing.T) {
	p := New("large-snapshot", "Large snapshot", "byedpi")
	label := strings.Repeat("a", 60)
	for i := 0; i < 4096; i++ {
		p.Routing.IncludeDomains = append(p.Routing.IncludeDomains, fmt.Sprintf("%s.%s.%s.%04d.example", label, label, label, i))
	}
	base, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	argumentSize := ((1<<20)-len(base)-4096)/128 - 3
	if argumentSize <= 0 || argumentSize > 4096 {
		t.Fatal("invalid boundary fixture", argumentSize)
	}
	for i := 0; i < 128; i++ {
		p.Args = append(p.Args, strings.Repeat("x", argumentSize))
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	compact, _ := json.Marshal(p)
	formatted, _ := json.MarshalIndent(p, "", "  ")
	if len(compact) > 1<<20 || len(formatted) < 1<<20 {
		t.Fatal("fixture did not span decoder limit", len(compact), len(formatted))
	}
	if err := ValidateSnapshot([]Profile{p}); err == nil {
		t.Fatal("backup accepted a profile it could not restore")
	}
}
