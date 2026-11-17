package fileinput

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
)

type observedInput struct {
	input
	buffers [][]byte
	read    func([]byte) (int, error)
	close   func() error
}

func (f *observedInput) Read(p []byte) (int, error) {
	f.buffers = append(f.buffers, p)
	if f.read != nil {
		return f.read(p)
	}
	return f.input.Read(p)
}
func (f *observedInput) Close() error {
	e := f.input.Close()
	if f.close != nil {
		e = errors.Join(e, f.close())
	}
	return e
}
func inputFile(t *testing.T, value []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "private-input")
	if e := os.WriteFile(p, value, 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func assertCleared(t *testing.T, f *observedInput) {
	t.Helper()
	for _, b := range f.buffers {
		for _, v := range b {
			if v != 0 {
				t.Fatal("failed snapshot left acquired bytes")
			}
		}
	}
}
func TestReadExactCapEmptyAndAbsence(t *testing.T) {
	for _, value := range [][]byte{nil, []byte("bounded private bytes")} {
		p := inputFile(t, value)
		got, e := Read(context.Background(), p, int64(len(value)))
		if e != nil || !bytes.Equal(got, value) {
			t.Fatal("exact cap", e)
		}
		clear(got)
	}
	p := inputFile(t, []byte("over"))
	called := false
	_, e := read(context.Background(), p, 3, func(string) (input, error) { called = true; return nil, nil })
	if e == nil || called {
		t.Fatal("overlimit data opened")
	}
	_, e = Read(context.Background(), filepath.Join(t.TempDir(), "missing"), 100)
	if !errors.Is(e, os.ErrNotExist) {
		t.Fatal("absence cause lost", e)
	}
}
func TestReadFaultsClearAndCloseBeforeReturn(t *testing.T) {
	for _, mode := range []string{"read", "close", "cancel-read", "cancel-close", "short", "grow", "mutate"} {
		t.Run(mode, func(t *testing.T) {
			if runtime.GOOS == "windows" && (mode == "grow" || mode == "mutate") {
				t.Skip("Windows exact-object read handle denies concurrent writes; native sharing test covers refusal")
			}
			p := inputFile(t, []byte("private-buffer"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("PRIVATE_PATH_CAUSE")
			var f *observedInput
			closed := 0
			got, e := read(ctx, p, 100, func(name string) (input, error) {
				real, q := openInput(name)
				if q != nil {
					return nil, q
				}
				f = &observedInput{input: real}
				f.close = func() error {
					closed++
					if mode == "cancel-close" {
						cancel()
					}
					if mode == "close" {
						return cause
					}
					return nil
				}
				switch mode {
				case "read":
					f.read = func(b []byte) (int, error) { n, q := real.Read(b); return n, errors.Join(q, cause) }
				case "cancel-read":
					f.read = func(b []byte) (int, error) { n, q := real.Read(b); cancel(); return n, q }
				case "short":
					f.read = func(b []byte) (int, error) {
						n, q := real.Read(b)
						if n > 0 {
							return n - 1, io.EOF
						}
						return n, q
					}
				case "grow":
					f.read = func(b []byte) (int, error) {
						n, q := real.Read(b)
						if n > 0 {
							w, z := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
							if z == nil {
								_, z = w.Write([]byte("x"))
								z = errors.Join(z, w.Close())
							}
							if z != nil {
								t.Fatal(z)
							}
						}
						return n, q
					}
				case "mutate":
					f.read = func(b []byte) (int, error) {
						n, q := real.Read(b)
						if n > 0 {
							state, z := StateFromPath(p, false)
							if z != nil {
								t.Fatal(z)
							}
							if z = os.Chtimes(p, state.Modified, state.Modified.Add(2000000000)); z != nil {
								t.Fatal(z)
							}
						}
						return n, q
					}
				}
				return f, nil
			})
			// Windows share-read deliberately prevents the injected writer/mtime edit;
			// these mutation cases are exercised separately on Unix.
			if e == nil || got != nil || closed != 1 {
				t.Fatal("fault returned data or did not close", mode, e, closed)
			}
			if (mode == "read" || mode == "close") && !errors.Is(e, cause) {
				t.Fatal("cause lost", e)
			}
			if strings.HasPrefix(mode, "cancel") && !errors.Is(e, context.Canceled) {
				t.Fatal("cancel cause lost", e)
			}
			if strings.Contains(e.Error(), "PRIVATE_PATH") || strings.Contains(e.Error(), p) {
				t.Fatal("private diagnostic")
			}
			assertCleared(t, f)
		})
	}
}
func TestReadCancellationBeforeOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	got, e := read(ctx, "missing", 100, func(string) (input, error) { called = true; return nil, nil })
	if got != nil || !errors.Is(e, context.Canceled) || called {
		t.Fatal("canceled operation opened input", e)
	}
}
func TestReadInitialReplacementAndHeldNamedMetadata(t *testing.T) {
	p := inputFile(t, []byte("same bytes"))
	old := p + ".old"
	readCalled := false
	_, e := read(context.Background(), p, 100, func(name string) (input, error) {
		if q := os.Rename(name, old); q != nil {
			t.Fatal(q)
		}
		if q := os.WriteFile(name, []byte("same bytes"), 0600); q != nil {
			t.Fatal(q)
		}
		f, q := openInput(name)
		if q != nil {
			return nil, q
		}
		return &observedInput{input: f, read: func([]byte) (int, error) { readCalled = true; return 0, io.EOF }}, nil
	})
	if e == nil || readCalled {
		t.Fatal("same-byte replacement accepted", e)
	}
	parent, e := OpenDirectory(filepath.Dir(p))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := parent.Close(); e != nil {
			t.Error(e)
		}
	}()
	held, e := StateFromPath(p, false)
	if e != nil {
		t.Fatal(e)
	}
	relative, e := StateAt(parent, filepath.Base(p), false)
	if e != nil || relative.Kind != fileidentity.Regular || held.ID != relative.ID {
		t.Fatal("held relative identity", e)
	}
}
