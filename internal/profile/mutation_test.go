package profile

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func assertMutationUncertain(t *testing.T, err error, causes ...error) {
	t.Helper()
	if !errors.Is(err, ErrMutationUncertain) || err.Error() != ErrMutationUncertain.Error() {
		t.Fatal("mutation uncertainty exposed a private error or lost its category")
	}
	for _, cause := range causes {
		if !errors.Is(err, cause) {
			t.Fatal("mutation uncertainty lost a body/context/Close cause")
		}
	}
}

// Every operation below is the same source locked body used by its public
// entrypoint. The actual fixture lease is already held. No test sets progress.
func mutationFixtureBody(f *listCloseFixture, action string) func(context.Context, *mutationProgress) error {
	return func(ctx context.Context, progress *mutationProgress) error {
		edited := f.original
		edited.Name = "Published mutation"
		switch action {
		case "save":
			return f.store.saveLockedContext(ctx, edited, progress)
		case "save-if":
			return f.store.saveIfUnchangedLockedContext(ctx, edited, f.store.getLockedContext, progress)
		case "delete":
			return f.store.deleteLocked(f.original.ID, progress)
		case "delete-if":
			return f.store.deleteIfUnchangedLockedContext(ctx, f.original.ID, f.original.UpdatedAt, f.store.getLockedContext, progress)
		case "seed":
			return f.store.seedLockedContext(ctx, []Profile{New("seed-first", "Seed published", "byedpi")}, progress)
		default:
			panic("invalid source-owned test action")
		}
	}
}

func mutationAssertPublished(t *testing.T, f *listCloseFixture, action string) {
	t.Helper()
	path, _ := f.store.filename(f.original.ID)
	switch action {
	case "delete", "delete-if":
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("actual deletion was undone or not published")
		}
	case "seed":
		p, err := f.store.Get("seed-first")
		if err != nil || p.Name != "Seed published" {
			t.Fatal("actual seeded profile was not retained")
		}
		marker, err := os.ReadFile(filepath.Join(f.store.Root, "presets-initialized"))
		if err != nil || !bytes.Equal(marker, []byte("1\n")) {
			t.Fatal("actual seed marker was not retained")
		}
	default:
		p, err := f.store.Get(f.original.ID)
		if err != nil || p.Name != "Published mutation" {
			t.Fatal("actual profile publication was not retained")
		}
	}
}

func TestProfileMutationPublicationAndLeaseCloseCofailure(t *testing.T) {
	for _, action := range []string{"save", "save-if", "delete", "delete-if", "seed"} {
		for _, cofault := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "-clean", true: "-close"}[cofault], func(t *testing.T) {
				f := newListCloseFixture(t)
				lease := f.acquire(t)
				cause := errors.New("PRIVATE_MUTATION_CLOSE")
				attempted := false
				body := mutationFixtureBody(f, action)
				err := mutateProfileSynchronously(context.Background(), func(ctx context.Context, p *mutationProgress) error {
					f.busy(t)
					err := body(ctx, p)
					attempted = p.effectsAttempted
					return err
				}, func() error {
					if err := lease.close(); err != nil {
						return err
					}
					if cofault {
						return &os.PathError{Op: "close", Path: "PRIVATE_MUTATION_LEASE", Err: cause}
					}
					return nil
				})
				if !attempted || lease.calls.Load() != 1 {
					t.Fatal("source effect progress or actual single Close missing")
				}
				if cofault {
					assertMutationUncertain(t, err, cause)
				} else if err != nil {
					t.Fatal("clean actual mutation failed", err)
				}
				mutationAssertPublished(t, f, action)
				next := f.acquire(t)
				if err := next.close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestProfileMutationPreeffectConflictIdentityAndCleanupPriority(t *testing.T) {
	for _, cofault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "close"}[cofault], func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			draft := f.original
			draft.UpdatedAt = time.Time{}
			cause := errors.New("PRIVATE_CONFLICT_CLOSE")
			attempted := false
			err := mutateProfileSynchronously(context.Background(), func(ctx context.Context, p *mutationProgress) error {
				err := f.store.saveIfUnchangedLockedContext(ctx, draft, f.store.getLockedContext, p)
				attempted = p.effectsAttempted
				return err
			}, func() error {
				if err := lease.close(); err != nil {
					return err
				}
				if cofault {
					return cause
				}
				return nil
			})
			if attempted {
				t.Fatal("refused revision was marked as a write attempt")
			}
			if cofault {
				assertMutationUncertain(t, err, ErrConflict, cause)
			} else if err != ErrConflict {
				t.Fatal("clean pre-effect primary identity changed")
			}
			got, readErr := f.store.Get(f.original.ID)
			if readErr != nil || got.Name != f.original.Name || !got.UpdatedAt.Equal(f.original.UpdatedAt) {
				t.Fatal("revision refusal changed existing profile")
			}
		})
	}
}

func TestProfileMutationPostAttemptFailureIsUncertain(t *testing.T) {
	f := newListCloseFixture(t)
	// The unconditional Delete actually invokes Remove. Even its NotExist result
	// is an attempted effect, not clean pre-read absence or a retry instruction.
	err := f.store.Delete("never-created")
	assertMutationUncertain(t, err, fs.ErrNotExist)
	// Force the real AtomicWrite path to fail at its parent-directory creation,
	// after save's source effect mark. No host ACL or filesystem fault is changed.
	profiles := filepath.Join(f.store.Root, "profiles")
	parked := profiles + ".owned-parked"
	if err := os.Rename(profiles, parked); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profiles, []byte("owned non-directory"), 0600); err != nil {
		t.Fatal(err)
	}
	err = f.store.Save(New("cannot-write", "Cannot write", "byedpi"))
	assertMutationUncertain(t, err)
	var native *os.PathError
	if !errors.As(err, &native) {
		t.Fatal("real writer error cause lost")
	}
	got, readErr := os.ReadFile(profiles)
	if readErr != nil || string(got) != "owned non-directory" {
		t.Fatal("failed write changed the non-directory fixture")
	}
}

func TestProfileMutationSeedPartialPublicationUsesOneStickyProgress(t *testing.T) {
	for _, cofault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "close"}[cofault], func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			first := New("seed-first", "First survives", "byedpi")
			invalid := New("seed-second", "", "byedpi")
			cause := errors.New("PRIVATE_SEED_CLOSE")
			var bodyErr error
			attempted := false
			err := mutateProfileSynchronously(context.Background(), func(ctx context.Context, p *mutationProgress) error {
				bodyErr = f.store.seedLockedContext(ctx, []Profile{first, invalid}, p)
				attempted = p.effectsAttempted
				return bodyErr
			}, func() error {
				if err := lease.close(); err != nil {
					return err
				}
				if cofault {
					return cause
				}
				return nil
			})
			if bodyErr == nil || !attempted {
				t.Fatal("actual partial seed validation/progress not observed")
			}
			assertMutationUncertain(t, err, bodyErr)
			if cofault && !errors.Is(err, cause) {
				t.Fatal("partial seed lost Close cofailure")
			}
			got, readErr := f.store.Get(first.ID)
			if readErr != nil || got.Name != first.Name {
				t.Fatal("earlier actual seed publication was rolled back")
			}
			for _, leaf := range []string{filepath.Join("profiles", invalid.ID+".json"), "presets-initialized"} {
				if _, err := os.Lstat(filepath.Join(f.store.Root, leaf)); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("failed seed invented later publication or completion marker")
				}
			}
			// The public entrypoint uses the same actual loop, and must also refuse a
			// false all-or-none result when this is the first failing seeding attempt.
			other := newListCloseFixture(t)
			assertMutationUncertain(t, other.store.Seed([]Profile{first, invalid}))
			retained, readErr := other.store.Get(first.ID)
			if readErr != nil || retained.Name != first.Name {
				t.Fatal("public partial Seed did not retain first profile")
			}
		})
	}
}

func TestProfileMutationSeedMarkerAndPreeffectBoundaries(t *testing.T) {
	for _, kind := range []string{"marker-present", "marker-only", "invalid-first"} {
		t.Run(kind, func(t *testing.T) {
			f := newListCloseFixture(t)
			if kind == "marker-present" {
				if err := f.store.Seed(nil); err != nil {
					t.Fatal(err)
				}
			}
			lease := f.acquire(t)
			fault := errors.New("PRIVATE_MARKER_CLOSE")
			attempted := false
			var bodyErr error
			err := mutateProfileSynchronously(context.Background(), func(ctx context.Context, p *mutationProgress) error {
				var samples []Profile
				if kind == "invalid-first" {
					samples = []Profile{New("invalid-first", "", "byedpi")}
				}
				bodyErr = f.store.seedLockedContext(ctx, samples, p)
				attempted = p.effectsAttempted
				return bodyErr
			}, func() error {
				if err := lease.close(); err != nil {
					return err
				}
				if kind != "invalid-first" {
					return fault
				}
				return nil
			})
			if kind == "invalid-first" {
				if attempted || bodyErr == nil || err != bodyErr || errors.Is(err, ErrMutationUncertain) {
					t.Fatal("invalid first sample lost exact pre-effect identity")
				}
				return
			}
			if attempted != (kind == "marker-only") {
				t.Fatal("seed progress not bound to actual marker write")
			}
			assertMutationUncertain(t, err, fault)
			marker, readErr := os.ReadFile(filepath.Join(f.store.Root, "presets-initialized"))
			if readErr != nil || string(marker) != "1\n" {
				t.Fatal("actual marker changed on cleanup error")
			}
		})
	}
}

func TestProfileMutationContextSampledAfterActualClose(t *testing.T) {
	f := newListCloseFixture(t)
	lease := f.acquire(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closeCause := errors.New("PRIVATE_CANCEL_CLOSE")
	err := mutateProfileSynchronously(ctx, mutationFixtureBody(f, "save"), func() error {
		if err := lease.close(); err != nil {
			return err
		}
		cancel()
		return closeCause
	})
	assertMutationUncertain(t, err, context.Canceled, closeCause)
	mutationAssertPublished(t, f, "save")
}

func TestProfileMutationBlockedCloseCannotAbandonPublishedScope(t *testing.T) {
	f := newListCloseFixture(t)
	lease := f.acquire(t)
	ctx, cancel := context.WithCancel(context.Background())
	entered, gate, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	var err error
	t.Cleanup(func() { cancel(); release(); listCloseCleanupWait(t, f, done) })
	go func() {
		defer close(done)
		err = mutateProfileSynchronously(ctx, mutationFixtureBody(f, "save"), func() error { close(entered); <-gate; return lease.close() })
	}()
	listCloseWait(t, f, entered)
	cancel()
	f.busy(t)
	select {
	case <-done:
		t.Fatal("canceled mutation abandoned actual blocked Close")
	default:
	}
	release()
	listCloseWait(t, f, done)
	assertMutationUncertain(t, err, context.Canceled)
	mutationAssertPublished(t, f, "save")
	next := f.acquire(t)
	if err := next.close(); err != nil {
		t.Fatal(err)
	}
}

func TestProfileMutationPanicKeepsPublishedBytesAndClosesActualLease(t *testing.T) {
	for _, cofault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "close"}[cofault], func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			original := &struct{ label string }{"PRIVATE_MUTATION_PANIC"}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_ = mutateProfileSynchronously(context.Background(), func(ctx context.Context, p *mutationProgress) error {
					if err := mutationFixtureBody(f, "save")(ctx, p); err != nil {
						t.Error("real pre-panic publication failed")
					}
					panic(original)
				}, func() error {
					if err := lease.close(); err != nil {
						return err
					}
					if cofault {
						return errors.New("PRIVATE_PANIC_CLOSE")
					}
					return nil
				})
			}()
			if recovered != original || lease.calls.Load() != 1 {
				t.Fatal("original panic or actual lease closure was lost")
			}
			mutationAssertPublished(t, f, "save")
			next := f.acquire(t)
			if err := next.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
