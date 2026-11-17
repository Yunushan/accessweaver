package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type hashOwnedReader struct {
	file                  *os.File
	readCause, closeCause error
	panicValue            any
	closes                int
	actualClose           error
}

func (r *hashOwnedReader) Read(p []byte) (int, error) {
	n, err := r.file.Read(p)
	if r.panicValue != nil {
		panic(r.panicValue)
	}
	if r.readCause != nil {
		return n, errors.Join(err, r.readCause)
	}
	return n, err
}
func (r *hashOwnedReader) Close() error {
	r.closes++
	r.actualClose = r.file.Close()
	// Inject a reported cofailure only after the real native Close succeeded.
	if r.actualClose != nil {
		return r.actualClose
	}
	return r.closeCause
}
func newHashOwnedReader(t *testing.T) *hashOwnedReader {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-hash-close-")
	if err != nil {
		t.Fatal("owned hash fixture unavailable")
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal("owned fixture identity unavailable")
	}
	path := filepath.Join(root, "source")
	if err = os.WriteFile(path, []byte("source-owned executable bytes"), 0600); err != nil {
		t.Fatal("owned source unavailable")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("owned reader unavailable")
	}
	r := &hashOwnedReader{file: f}
	t.Cleanup(func() {
		if r.closes == 0 {
			r.closes++
			r.actualClose = f.Close()
		}
		if r.actualClose != nil {
			t.Error("unconfirmed hash fixture retained")
			return
		}
		current, err := os.Lstat(root)
		if err != nil || !os.SameFile(info, current) {
			t.Error("changed fixture retained")
			return
		}
		if err = os.RemoveAll(root); err != nil {
			t.Error("owned fixture cleanup failed")
		}
	})
	return r
}
func TestExecutableHashCompletionRetainsReadAndCloseCauses(t *testing.T) {
	for _, mode := range []string{"clean", "read", "close", "both"} {
		t.Run(mode, func(t *testing.T) {
			r := newHashOwnedReader(t)
			readCause := errors.New("PRIVATE_READ_CAUSE")
			closeCause := &os.PathError{Op: "PRIVATE_CLOSE", Path: "PRIVATE_SOURCE_PATH", Err: errors.New("PRIVATE_CLOSE_CAUSE")}
			if mode == "read" || mode == "both" {
				r.readCause = readCause
			}
			if mode == "close" || mode == "both" {
				r.closeCause = closeCause
			}
			digest, err := executableHash(r)
			if r.closes != 1 || r.actualClose != nil {
				t.Fatal("actual reader Close not confirmed exactly once")
			}
			if n, probe := r.file.Read(make([]byte, 1)); n != 0 || !errors.Is(probe, os.ErrClosed) {
				t.Fatal("actual file remained open")
			}
			if mode == "clean" {
				sum := sha256.Sum256([]byte("source-owned executable bytes"))
				if err != nil || digest != hex.EncodeToString(sum[:]) {
					t.Fatal("clean observed hash changed")
				}
			} else {
				if digest != "" || !errors.Is(err, errExecutableHashUnavailable) || err.Error() != errExecutableHashUnavailable.Error() {
					t.Fatal("uncertain hash exposed digest or private error")
				}
				if r.readCause != nil && !errors.Is(err, readCause) {
					t.Fatal("read cause lost")
				}
				if r.closeCause != nil {
					var original *os.PathError
					if !errors.As(err, &original) || original != closeCause {
						t.Fatal("Close cause replaced")
					}
				}
			}
		})
	}
}
func TestExecutableHashCompletionPanicClosesOriginalReader(t *testing.T) {
	r := newHashOwnedReader(t)
	original := &struct{ tag string }{"PRIVATE_PANIC"}
	r.panicValue = original
	var recovered any
	func() { defer func() { recovered = recover() }(); _, _ = executableHash(r) }()
	if recovered != original || r.closes != 1 || r.actualClose != nil {
		t.Fatal("body panic or owned Close lost")
	}
	if n, err := r.file.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatal("panic left reader open")
	}
}

var _ io.ReadCloser = (*hashOwnedReader)(nil)
