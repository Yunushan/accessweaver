package profile

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/filelock"
)

func assertReadUnavailable(t *testing.T, p Profile, err error, causes ...error) {
	t.Helper()
	if !reflect.DeepEqual(p, Profile{}) || !errors.Is(err, ErrReadUnavailable) || err.Error() != ErrReadUnavailable.Error() {
		t.Fatal("uncertain read exposed a profile or private error")
	}
	for _, cause := range causes {
		if !errors.Is(err, cause) {
			t.Fatal("read lost a private cause")
		}
	}
}

func TestProfileReadSnapshotBoundaryAndCleanAbsence(t *testing.T) {
	f := newListCloseFixture(t)
	path, _ := f.store.filename(f.original.ID)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	padded := append(bytes.Clone(original), bytes.Repeat([]byte(" "), (1<<20)-len(original))...)
	if err := os.WriteFile(path, padded, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := f.store.GetContext(context.Background(), f.original.ID)
	if err != nil || !reflect.DeepEqual(p, f.original) {
		t.Fatal("exact one MiB valid snapshot rejected")
	}
	if err := os.WriteFile(path, append(padded, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	p, err = f.store.GetContext(context.Background(), f.original.ID)
	assertReadUnavailable(t, p, err, fileinput.ErrUnavailable)
	// Known absence remains the creation path. It is never inferred from an
	// error after an existing regular file has been observed.
	p, err = f.store.GetContext(context.Background(), "missing-profile")
	if !reflect.DeepEqual(p, Profile{}) || !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrReadUnavailable) {
		t.Fatal("clean initial absence changed")
	}
	fresh := New("missing-profile", "Created", "byedpi")
	if err := f.store.SaveIfUnchangedContext(context.Background(), fresh); err != nil {
		t.Fatal("known absence creation refused", err)
	}
	if _, err := f.store.Get(fresh.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeleteIfUnchangedContext(context.Background(), "never-created", time.Time{}); err != ErrConflict {
		t.Fatal("known absence delete conflict changed")
	}
	if err := os.Mkdir(filepath.Join(f.store.Root, "profiles", "special-profile.json"), 0700); err != nil {
		t.Fatal(err)
	}
	p, err = f.store.Get("special-profile")
	assertReadUnavailable(t, p, err)
}

func TestProfileReadClearsOwnedSnapshotAndRetainsDecodeSemantics(t *testing.T) {
	for _, kind := range []string{"valid", "decode", "mismatch", "snapshot-error", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newListCloseFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fault := errors.New("PRIVATE_SNAPSHOT_CLOSE")
			var acquired []byte
			p, err := f.store.getLockedContextWithRead(ctx, f.original.ID, func(ctx context.Context, path string, limit int64) ([]byte, error) {
				if limit != 1<<20 {
					t.Fatal("snapshot budget changed")
				}
				data, err := fileinput.Read(ctx, path, limit)
				if err != nil {
					return nil, err
				}
				switch kind {
				case "decode":
					data[0] = '!'
				case "mismatch":
					copy(data[bytes.Index(data, []byte(f.original.ID)):], []byte("other-profile"))
				case "snapshot-error":
					acquired = data
					return data, &os.PathError{Op: "close", Path: "PRIVATE_SNAPSHOT", Err: fault}
				case "cancel":
					cancel()
				}
				acquired = data
				return data, nil
			})
			if len(acquired) == 0 || !bytes.Equal(acquired, make([]byte, len(acquired))) {
				t.Fatal("owned raw snapshot not cleared")
			}
			switch kind {
			case "valid":
				if err != nil || !reflect.DeepEqual(p, f.original) {
					t.Fatal("valid snapshot changed")
				}
			case "snapshot-error":
				assertReadUnavailable(t, p, err, fault)
			case "cancel":
				assertReadUnavailable(t, p, err, context.Canceled)
			default:
				if err == nil || !reflect.DeepEqual(p, Profile{}) || errors.Is(err, ErrReadUnavailable) {
					t.Fatal("semantic decode/ID rejection changed")
				}
			}
		})
	}
}

func TestProfileReadLeaseCompletionGatesDataAndCofailures(t *testing.T) {
	for _, kind := range []string{"valid", "body-error", "close", "body-close", "cancel-close", "missing-close"} {
		t.Run(kind, func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bodyCause := errors.New("PRIVATE_BODY")
			closeCause := errors.New("PRIVATE_LEASE_CLOSE")
			var bodyErr error
			p, err := readProfileSynchronously(ctx, func(ctx context.Context) (Profile, error) {
				f.busy(t)
				p, e := f.store.getLockedContext(ctx, f.original.ID)
				if e != nil {
					return p, e
				}
				switch kind {
				case "body-error", "body-close":
					bodyErr = bodyCause
					return p, bodyErr
				case "missing-close":
					bodyErr = &os.PathError{Op: "lstat", Path: "PRIVATE_MISSING", Err: fs.ErrNotExist}
					return Profile{}, bodyErr
				}
				return p, nil
			}, func() error {
				if err := lease.close(); err != nil {
					return err
				}
				if kind == "cancel-close" {
					cancel()
				}
				if kind == "close" || kind == "body-close" || kind == "cancel-close" || kind == "missing-close" {
					return &os.PathError{Op: "close", Path: "PRIVATE_LEASE", Err: closeCause}
				}
				return nil
			})
			if lease.calls.Load() != 1 {
				t.Fatal("real lease Close skipped/repeated")
			}
			switch kind {
			case "valid":
				if err != nil || !reflect.DeepEqual(p, f.original) {
					t.Fatal("confirmed read changed")
				}
			case "body-error":
				if err != bodyCause || !reflect.DeepEqual(p, Profile{}) {
					t.Fatal("clean Close lost exact primary identity")
				}
			case "body-close":
				assertReadUnavailable(t, p, err, bodyCause, closeCause)
			case "cancel-close":
				assertReadUnavailable(t, p, err, context.Canceled, closeCause)
			case "missing-close":
				assertReadUnavailable(t, p, err, fs.ErrNotExist, closeCause)
			default:
				assertReadUnavailable(t, p, err, closeCause)
			}
			next := f.acquire(t)
			if err := next.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProfileReadBlockedLeaseCloseRetainsOwnerThroughCancellation(t *testing.T) {
	f := newListCloseFixture(t)
	lease := f.acquire(t)
	ctx, cancel := context.WithCancel(context.Background())
	entered, gate, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	var p Profile
	var err error
	t.Cleanup(func() { cancel(); release(); listCloseCleanupWait(t, f, done) })
	go func() {
		defer close(done)
		p, err = readProfileSynchronously(ctx, func(ctx context.Context) (Profile, error) { return f.store.getLockedContext(ctx, f.original.ID) }, func() error { close(entered); <-gate; return lease.close() })
	}()
	listCloseWait(t, f, entered)
	cancel()
	f.busy(t)
	select {
	case <-done:
		t.Fatal("read abandoned owned blocked Close")
	default:
	}
	release()
	listCloseWait(t, f, done)
	assertReadUnavailable(t, p, err, context.Canceled)
	next := f.acquire(t)
	if err := next.close(); err != nil {
		t.Fatal(err)
	}
}

func TestProfileReadPanicStillClosesLease(t *testing.T) {
	for _, cofault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "cofault"}[cofault], func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			original := &struct{ label string }{"PRIVATE_PANIC"}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_, _ = readProfileSynchronously(context.Background(), func(ctx context.Context) (Profile, error) {
					if _, err := f.store.getLockedContext(ctx, f.original.ID); err != nil {
						t.Error("real read failed")
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
				t.Fatal("body panic or actual lease Close lost")
			}
			next := f.acquire(t)
			if err := next.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProfileReadUncertainMissingNeverAuthorizesMutation(t *testing.T) {
	for _, action := range []string{"save", "delete"} {
		t.Run(action, func(t *testing.T) {
			f := newListCloseFixture(t)
			path, _ := f.store.filename(f.original.ID)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			read := func(ctx context.Context, id string) (Profile, error) {
				return f.store.getLockedContextWithRead(ctx, id, func(ctx context.Context, path string, limit int64) ([]byte, error) {
					parked := path + ".owned-parked"
					if err := os.Rename(path, parked); err != nil {
						return nil, err
					}
					data, readErr := fileinput.Read(ctx, path, limit)
					if err := os.Rename(parked, path); err != nil {
						f.preserve.Store(true)
						return nil, errors.Join(readErr, err)
					}
					return data, readErr
				})
			}
			if action == "save" {
				replacement := f.original
				replacement.UpdatedAt = time.Time{}
				replacement.Name = "Must never replace"
				err = f.store.saveIfUnchangedContext(context.Background(), replacement, read)
			} else {
				err = f.store.deleteIfUnchangedContext(context.Background(), f.original.ID, f.original.UpdatedAt, read)
			}
			if !errors.Is(err, ErrReadUnavailable) || !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrConflict) || err.Error() != ErrReadUnavailable.Error() {
				t.Fatal("post-observation missing became clean absence/conflict")
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("uncertain pre-read changed profile bytes")
			}
		})
	}
}

func TestProfileReadRestoreRefusalRetainsCloseCofailure(t *testing.T) {
	for _, kind := range []string{"clean", "close", "cancel", "cancel-close"} {
		t.Run(kind, func(t *testing.T) {
			f := newListCloseFixture(t)
			lease := f.acquire(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			marker := filepath.Join(f.store.Root, restoreMarker)
			if err := os.WriteFile(marker, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			body := checkRestoreState(f.store.Root)
			if body != ErrRestoreIncomplete {
				t.Fatal("owned restore marker did not produce the exact restore refusal")
			}
			fault := errors.New("PRIVATE_RESTORE_CLOSE")
			p, got := readProfileSynchronously(ctx, func(context.Context) (Profile, error) {
				return Profile{}, checkRestoreState(f.store.Root)
			}, func() error {
				if err := lease.close(); err != nil {
					return err
				}
				if kind == "cancel" || kind == "cancel-close" {
					cancel()
				}
				if kind == "close" || kind == "cancel-close" {
					return fault
				}
				return nil
			})
			if kind == "clean" {
				if got != body || !reflect.DeepEqual(p, Profile{}) {
					t.Fatal("clean completion changed restore refusal identity")
				}
			} else {
				causes := []error{body}
				if kind == "cancel" || kind == "cancel-close" {
					causes = append(causes, context.Canceled)
				}
				if kind == "close" || kind == "cancel-close" {
					causes = append(causes, fault)
				}
				assertReadUnavailable(t, p, got, causes...)
			}
			if lease.calls.Load() != 1 {
				t.Fatal("restore refusal skipped or repeated actual Close")
			}
			// Actual native reacquisition independently proves release.
			next, err := filelock.TryAcquire(filepath.Join(f.store.Root, ".profiles.lock"))
			if err != nil {
				f.preserve.Store(true)
				t.Fatal("real lease remained held")
			}
			if err := next.Close(); err != nil {
				f.preserve.Store(true)
				t.Fatal(err)
			}
		})
	}
}
