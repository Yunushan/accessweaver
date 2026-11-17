//go:build linux || darwin || freebsd || openbsd

package fileinput

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadRacedFIFOAndSymlinkNeverRead(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root, e := os.MkdirTemp("", "accessweaver-input-kind-")
			if e != nil {
				t.Fatal(e)
			}
			clean := false
			defer func() {
				if clean {
					if e := os.RemoveAll(root); e != nil {
						t.Error(e)
					}
				}
			}()
			path := filepath.Join(root, "input")
			old := filepath.Join(root, "original")
			if e = os.WriteFile(path, []byte("secret"), 0600); e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			readCalled := false
			setupErr := errors.New("owned race fixture setup failed")
			go func() {
				_, e := read(context.Background(), path, 100, func(name string) (input, error) {
					if e := os.Rename(name, old); e != nil {
						return nil, errors.Join(setupErr, e)
					}
					if kind == "fifo" {
						if e := syscall.Mkfifo(name, 0600); e != nil {
							return nil, errors.Join(setupErr, e)
						}
					} else if e := os.Symlink(old, name); e != nil {
						return nil, errors.Join(setupErr, e)
					}
					real, e := openInput(name)
					if e != nil {
						return nil, e
					}
					return &observedInput{input: real, read: func(p []byte) (int, error) { readCalled = true; return real.Read(p) }}, nil
				})
				done <- e
			}()
			select {
			case e := <-done:
				clean = true
				if e == nil || readCalled || errors.Is(e, setupErr) {
					t.Fatal("special accepted or data read attempted")
				}
			case <-time.After(3 * time.Second):
				// A broken blocking-open implementation is released by a separately owned
				// nonblocking FIFO writer. Join before deleting any test-owned evidence.
				writer, q := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
				if q == nil {
					q = writer.Close()
				}
				if q != nil && !errors.Is(q, syscall.ENXIO) {
					t.Error(q)
				}
				select {
				case <-done:
					clean = true
				case <-time.After(time.Second):
				}
				t.Fatal("special-file open blocked; root preserved unless actual read joined")
			}
		})
	}
}
func TestAbsoluteNamePreservesUnixSymlinkDotDotTraversal(t *testing.T) {
	root := t.TempDir()
	physical := filepath.Join(root, "physical")
	nested := filepath.Join(physical, "nested")
	if e := os.MkdirAll(nested, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(physical, "input"), []byte("physical"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "input"), []byte("lexical"), 0600); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(root, "alias")
	if e := os.Symlink(nested, alias); e != nil {
		t.Fatal(e)
	}
	got, e := Read(context.Background(), alias+"/../input", 100)
	if e != nil || string(got) != "physical" {
		t.Fatal("relative spelling changed traversal", e)
	}
}

func TestReadActualShrinkAndSameBytesNamedReplacement(t *testing.T) {
	for _, mode := range []string{"shrink", "replace"} {
		t.Run(mode, func(t *testing.T) {
			path := inputFile(t, []byte("private source bytes"))
			original, e := StateFromPath(path, false)
			if e != nil {
				t.Fatal(e)
			}
			var f *observedInput
			changed := false
			data, e := read(context.Background(), path, 100, func(name string) (input, error) {
				real, e := openInput(name)
				if e != nil {
					return nil, e
				}
				f = &observedInput{input: real}
				f.read = func(p []byte) (int, error) {
					if changed {
						return real.Read(p)
					}
					changed = true
					if mode == "shrink" {
						n, q := real.Read(p[:3])
						if e := os.Truncate(name, 3); e != nil {
							t.Fatal(e)
						}
						return n, q
					}
					n, q := real.Read(p)
					if e := os.Rename(name, name+".original"); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(name, []byte("private source bytes"), 0600); e != nil {
						t.Fatal(e)
					}
					if e := os.Chtimes(name, original.Modified, original.Modified); e != nil {
						t.Fatal(e)
					}
					return n, q
				}
				return f, nil
			})
			if data != nil || e == nil || !changed {
				t.Fatal("changed source accepted", mode, e)
			}
			assertCleared(t, f)
		})
	}
}
