package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type backupFaultOutput struct {
	backupOutputFile
	write func([]byte) (int, error)
	sync  func() error
	close func() error
}

func (f *backupFaultOutput) Write(p []byte) (int, error) {
	if f.write != nil {
		return f.write(p)
	}
	return f.backupOutputFile.Write(p)
}
func (f *backupFaultOutput) Sync() error {
	e := f.backupOutputFile.Sync()
	if f.sync != nil {
		e = errors.Join(e, f.sync())
	}
	return e
}
func (f *backupFaultOutput) Close() error {
	e := f.backupOutputFile.Close()
	if f.close != nil {
		e = errors.Join(e, f.close())
	}
	return e
}
func backupOutputFixture(t *testing.T) (*backupOutput, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if e := os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "private.awbackup")
	o, e := prepareBackupOutput(context.Background(), path, source)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := o.Close(); e != nil {
			t.Error(e)
		}
	})
	return o, path
}
func TestBackupOutputActualFaultCompositionAndPreservation(t *testing.T) {
	for _, mode := range []string{"short", "write", "sync", "close", "cancel", "cofailure"} {
		t.Run(mode, func(t *testing.T) {
			o, path := backupOutputFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writeCause := errors.New("PRIVATE_WRITE_PATH")
			syncCause := errors.New("PRIVATE_SYNC_PATH")
			closeCause := errors.New("PRIVATE_CLOSE_PATH")
			closes := 0
			syncs := 0
			e := o.write(ctx, []byte("encrypted archive bytes"), func(parent *os.File, name string) (backupOutputFile, error) {
				real, q := createBackupOutput(parent, name)
				if q != nil {
					return nil, q
				}
				f := &backupFaultOutput{backupOutputFile: real}
				f.close = func() error {
					closes++
					if mode == "close" || mode == "cofailure" {
						return closeCause
					}
					return nil
				}
				f.sync = func() error {
					syncs++
					if mode == "sync" || mode == "cofailure" {
						return syncCause
					}
					return nil
				}
				f.write = func(p []byte) (int, error) {
					if mode == "short" {
						return real.Write(p[:3])
					}
					n, q := real.Write(p)
					if mode == "write" || mode == "cofailure" {
						q = errors.Join(q, writeCause)
					}
					if mode == "cancel" {
						cancel()
					}
					return n, q
				}
				return f, nil
			})
			if e == nil || closes != 1 || syncs != 1 {
				t.Fatal("write fault lost owner", e, closes, syncs)
			}
			if mode == "short" && !errors.Is(e, io.ErrShortWrite) {
				t.Fatal("short write not retained", e)
			}
			if mode == "cofailure" && (!errors.Is(e, writeCause) || !errors.Is(e, syncCause) || !errors.Is(e, closeCause)) {
				t.Fatal("cofailure erased", e)
			}
			if mode == "cancel" && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation erased", e)
			}
			if strings.Contains(e.Error(), "PRIVATE_") || strings.Contains(e.Error(), path) {
				t.Fatal("private error printed", e)
			}
			got, q := os.ReadFile(path)
			if q != nil || len(got) == 0 {
				t.Fatal("partial was deleted", q)
			}
		})
	}
}
func TestBackupOutputCancelBeforeEffectsAndExclusiveDestination(t *testing.T) {
	o, path := backupOutputFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	e := o.write(ctx, []byte("archive"), func(*os.File, string) (backupOutputFile, error) { called = true; return nil, nil })
	if !errors.Is(e, context.Canceled) || called {
		t.Fatal("canceled create performed effects", e)
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("unexpected output", e)
	}
	o, path = backupOutputFixture(t)
	original := []byte("existing private evidence")
	if e = os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	e = o.Write(context.Background(), []byte("replacement"))
	got, q := os.ReadFile(path)
	if !errors.Is(e, os.ErrExist) || q != nil || !bytes.Equal(got, original) {
		t.Fatal("existing output changed", e, q)
	}
}
func TestBackupContextBeforePassphraseAndFixedSourceError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := backupCommandContext(ctx, []string{"inspect", "--archive", "PRIVATE_ARCHIVE", "--passphrase-file", "PRIVATE_PASSWORD"}, t.TempDir())
	if !errors.Is(e, context.Canceled) || strings.Contains(e.Error(), "PRIVATE_") {
		t.Fatal("context or privacy lost", e)
	}
}

func TestBackupOutputNativeAncestorIdentityRefusesSource(t *testing.T) {
	// Production passes a resolved parent to the strict ancestry helper.
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(root, "source")
	child := filepath.Join(source, "child")
	if e := os.MkdirAll(child, 0700); e != nil {
		t.Fatal(e)
	}
	state, e := fileinput.StateFromPath(source, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = backupOutputAncestry(context.Background(), child, state.ID); e == nil {
		t.Fatal("native source ancestor accepted")
	}
	if e = backupOutputAncestry(context.Background(), root, state.ID); e != nil {
		t.Fatal("outside parent refused", e)
	}
}
func TestBackupOutputCaseAliasCannotCreateInsideSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "MixedSource")
	if e := os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(root, "mixedsource")
	actual, e := fileinput.StateFromPath(source, false)
	if e != nil {
		t.Fatal(e)
	}
	candidate, e := fileinput.StateFromPath(alias, false)
	if errors.Is(e, os.ErrNotExist) {
		t.Skip("owned filesystem distinguishes case spellings")
	}
	if e != nil || candidate.ID != actual.ID {
		t.Fatal("case-alias fixture state", e)
	}
	result, e := prepareBackupOutput(context.Background(), filepath.Join(alias, "archive"), source)
	if result != nil {
		q := result.Close()
		t.Fatal("source alias accepted", q)
	}
	if e == nil {
		t.Fatal("source alias missing refusal")
	}
	if _, q := os.Lstat(filepath.Join(source, "archive")); !os.IsNotExist(q) {
		t.Fatal("source artifact created", q)
	}
}
