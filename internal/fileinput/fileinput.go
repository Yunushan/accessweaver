// Package fileinput owns bounded snapshots of explicitly selected files.
// Native identity is a conflict detector, never an actor or permission grant.
package fileinput

import (
	"context"
	"errors"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"io"
	"math"
	"os"
	"path/filepath"
)

var ErrUnavailable = errors.New("selected file input is unavailable or changed")

type failure struct{ cause error }

func (e *failure) Error() string   { return ErrUnavailable.Error() }
func (e *failure) Unwrap() []error { return []error{ErrUnavailable, e.cause} }
func fail(e error) error {
	if e == nil {
		return nil
	}
	return &failure{e}
}

// StateFromFile borrows f throughout an eager native query, without reading or
// closing it. No audit-specific SID or local-volume namespace policy applies.
func StateFromFile(f *os.File) (fileidentity.State, error) {
	s, e := stateFromFile(f)
	return s, fail(e)
}

// StateFromPath closes its owned metadata probe before returning.
func StateFromPath(path string, followLinks bool) (fileidentity.State, error) {
	s, e := stateFromPath(path, followLinks)
	return s, fail(e)
}
func OpenDirectory(path string) (*os.File, error) { f, e := openDirectory(path); return f, fail(e) }

// StateAt observes one leaf relative to the held directory descriptor.
func StateAt(parent *os.File, name string, followLinks bool) (fileidentity.State, error) {
	if parent == nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fileidentity.State{}, fail(ErrUnavailable)
	}
	s, e := stateAt(parent, name, followLinks)
	return s, fail(e)
}

// AbsoluteName snapshots relative spelling without changing Unix symlink/..
// traversal. Windows uses ordinary DOS path resolution.
func AbsoluteName(path string) (string, error) { s, e := absoluteName(path); return s, fail(e) }

type input interface {
	io.Reader
	State() (fileidentity.State, error)
	Close() error
}
type fileOwner struct {
	*os.File
	metadata *os.File
}

func (f *fileOwner) State() (fileidentity.State, error) { return StateFromFile(f.File) }
func (f *fileOwner) Close() error {
	e := f.File.Close()
	if f.metadata != nil {
		e = errors.Join(e, f.metadata.Close())
	}
	return e
}
func same(a, b fileidentity.State) bool {
	return a.Kind == fileidentity.Regular && b.Kind == fileidentity.Regular && a.ID == b.ID && a.Size == b.Size && a.Modified.Equal(b.Modified)
}

// Read returns data only after EOF, unchanged eager held/named state and every
// checked Close. One allocation permits clearing all acquired bytes on failure.
// Native I/O is synchronous: context cancellation never abandons a worker.
func Read(ctx context.Context, path string, limit int64) ([]byte, error) {
	return read(ctx, path, limit, openInput)
}
func read(ctx context.Context, path string, limit int64, open func(string) (input, error)) (data []byte, err error) {
	if ctx == nil {
		return nil, fail(ErrUnavailable)
	}
	if e := ctx.Err(); e != nil {
		return nil, fail(e)
	}
	if limit < 0 || limit >= int64(math.MaxInt) {
		return nil, fail(ErrUnavailable)
	}
	name, e := AbsoluteName(path)
	if e != nil {
		return nil, e
	}
	initial, e := StateFromPath(name, false)
	if e != nil {
		return nil, e
	}
	if initial.Kind != fileidentity.Regular || initial.Size < 0 || initial.Size > limit {
		return nil, fail(ErrUnavailable)
	}
	if e = ctx.Err(); e != nil {
		return nil, fail(e)
	}
	f, e := open(name)
	if e != nil {
		if f != nil {
			e = errors.Join(e, f.Close())
		}
		return nil, fail(errors.Join(e, ctx.Err()))
	}
	if f == nil {
		return nil, fail(ErrUnavailable)
	}
	var buffer []byte
	defer func() {
		err = errors.Join(err, f.Close(), ctx.Err())
		if err != nil {
			clear(buffer)
			data = nil
			err = fail(err)
		}
	}()
	held, e := f.State()
	if e != nil {
		return nil, e
	}
	if !same(initial, held) {
		return nil, ErrUnavailable
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	buffer = make([]byte, int(initial.Size)+1)
	actual := 0
	eof := false
	for !eof {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		n, re := f.Read(buffer[actual:])
		if n < 0 || n > len(buffer)-actual {
			return nil, ErrUnavailable
		}
		actual += n
		if e = ctx.Err(); e != nil {
			return nil, errors.Join(re, e)
		}
		if int64(actual) > initial.Size || int64(actual) > limit {
			return nil, errors.Join(ErrUnavailable, re)
		}
		if re == io.EOF {
			eof = true
		} else if re != nil {
			return nil, re
		} else if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
	if int64(actual) != initial.Size {
		return nil, ErrUnavailable
	}
	after, e := f.State()
	if e != nil {
		return nil, e
	}
	named, e := StateFromPath(name, false)
	if e != nil {
		return nil, e
	}
	if !same(held, after) || !same(after, named) {
		return nil, ErrUnavailable
	}
	data = buffer[:actual]
	return data, nil
}
