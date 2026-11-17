package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/privatefile"
)

type backupStageError struct {
	message string
	cause   error
}

func (e *backupStageError) Error() string { return e.message }
func (e *backupStageError) Unwrap() error { return e.cause }
func backupFailure(message string, cause error) error {
	if cause == nil {
		return nil
	}
	return &backupStageError{message, cause}
}

const backupOutputFailure = "backup output incomplete; preserve any created file for inspection and do not distribute"

type backupOutput struct {
	parent   *os.File
	leaf     string
	id       fileidentity.ID
	closed   bool
	closeErr error
}

// prepareBackupOutput binds the boundary-checked parent to a retained native
// directory. Creation is descriptor-relative; retargeting the original path
// cannot redirect the new child into the source tree.
func prepareBackupOutput(ctx context.Context, path, source string) (result *backupOutput, err error) {
	if e := ctx.Err(); e != nil {
		return nil, backupFailure("backup operation canceled", e)
	}
	absolute, e := fileinput.AbsoluteName(path)
	if e != nil {
		return nil, backupFailure(backupOutputFailure, e)
	}
	parentName, leaf := filepath.Split(absolute)
	if leaf == "" || leaf == "." || leaf == ".." {
		return nil, backupFailure(backupOutputFailure, os.ErrInvalid)
	}
	resolved, e := filepath.EvalSymlinks(parentName)
	if e != nil {
		return nil, backupFailure(backupOutputFailure, e)
	}
	parent, e := fileinput.OpenDirectory(resolved)
	if e != nil {
		return nil, backupFailure(backupOutputFailure, e)
	}
	defer func() {
		if err != nil {
			err = backupFailure(backupOutputFailure, errors.Join(err, parent.Close()))
		}
	}()
	held, e := fileinput.StateFromFile(parent)
	if e != nil || held.Kind != fileidentity.Directory {
		return nil, errors.Join(os.ErrInvalid, e)
	}
	canonical, e := filepath.EvalSymlinks(parentName)
	if e != nil {
		return nil, e
	}
	named, e := fileinput.StateFromPath(canonical, false)
	if e != nil || named.Kind != fileidentity.Directory || named.ID != held.ID {
		return nil, errors.Join(os.ErrInvalid, e)
	}
	sourceRoot, e := filepath.EvalSymlinks(source)
	if e != nil {
		return nil, e
	}
	sourceRoot, e = filepath.Abs(sourceRoot)
	if e != nil {
		return nil, e
	}
	relative, e := filepath.Rel(sourceRoot, filepath.Join(canonical, leaf))
	if e == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, errors.New("backup output must be outside the source data directory")
	}
	sourceState, e := fileinput.StateFromPath(sourceRoot, false)
	if e != nil || sourceState.Kind != fileidentity.Directory {
		return nil, errors.Join(os.ErrInvalid, e)
	}
	if e = backupOutputAncestry(ctx, canonical, sourceState.ID); e != nil {
		return nil, e
	}
	rebound, e := fileinput.StateFromPath(canonical, false)
	if e != nil || rebound.Kind != fileidentity.Directory || rebound.ID != held.ID {
		return nil, errors.Join(os.ErrInvalid, e)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return &backupOutput{parent: parent, leaf: leaf, id: held.ID}, nil
}

// Native ancestor IDs complement lexical Rel on filesystems whose case or
// normalization rules differ from filepath. This is a finite chain of metadata
// observations, not enumeration or protection against concurrent ancestor moves.
func backupOutputAncestry(ctx context.Context, parent string, source fileidentity.ID) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		state, e := fileinput.StateFromPath(parent, false)
		if e != nil {
			return e
		}
		if state.Kind != fileidentity.Directory {
			return os.ErrInvalid
		}
		if state.ID == source {
			return errors.New("backup output must be outside the source data directory")
		}
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
	}
}
func (o *backupOutput) Close() error {
	if !o.closed {
		o.closed = true
		o.closeErr = o.parent.Close()
	}
	return o.closeErr
}

type backupOutputFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
	State() (fileidentity.State, error)
}
type backupOutputOwner struct{ *os.File }

func (f backupOutputOwner) State() (fileidentity.State, error) {
	return fileinput.StateFromFile(f.File)
}
func createBackupOutput(parent *os.File, leaf string) (backupOutputFile, error) {
	f, e := privatefile.CreateAt(parent, leaf)
	if e != nil {
		return nil, e
	}
	return backupOutputOwner{f}, nil
}
func (o *backupOutput) Write(ctx context.Context, data []byte) error {
	return o.write(ctx, data, createBackupOutput)
}
func (o *backupOutput) write(ctx context.Context, data []byte, create func(*os.File, string) (backupOutputFile, error)) (err error) {
	defer func() { err = backupFailure(backupOutputFailure, errors.Join(err, o.Close(), ctx.Err())) }()
	if e := ctx.Err(); e != nil {
		return e
	}
	parent, e := fileinput.StateFromFile(o.parent)
	if e != nil || parent.Kind != fileidentity.Directory || parent.ID != o.id {
		return errors.Join(os.ErrInvalid, e)
	}
	f, e := create(o.parent, o.leaf)
	if e != nil {
		if f != nil {
			e = errors.Join(e, f.Close())
		}
		return e
	}
	if f == nil {
		return os.ErrInvalid
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	initial, e := f.State()
	if e != nil || initial.Kind != fileidentity.Regular || initial.Size != 0 {
		return errors.Join(os.ErrInvalid, e)
	}
	named, e := fileinput.StateAt(o.parent, o.leaf, false)
	if e != nil || named.Kind != fileidentity.Regular || named.ID != initial.ID || named.Size != 0 {
		return errors.Join(os.ErrInvalid, e)
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	n, writeErr := f.Write(data)
	if n != len(data) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	// Sync and every Close are observed even after a partial write. The partial
	// object is retained; there is no retry or deletion on failure.
	syncErr := f.Sync()
	after, stateErr := f.State()
	named, namedErr := fileinput.StateAt(o.parent, o.leaf, false)
	var changed error
	if after.Kind != fileidentity.Regular || after.ID != initial.ID || after.Size != int64(n) || named.Kind != fileidentity.Regular || named.ID != after.ID || named.Size != after.Size || !named.Modified.Equal(after.Modified) {
		changed = os.ErrInvalid
	}
	return errors.Join(writeErr, syncErr, stateErr, namedErr, changed, ctx.Err())
}
