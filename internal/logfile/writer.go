// Package logfile bounds persistent child-process logs by rotating fixed-size files.
package logfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

type Writer struct {
	mu      sync.Mutex
	path    string
	limit   int64
	backups int
	file    *os.File
	size    int64
	err     error
	closed  bool
}

// Open appends to path and retains at most backups numbered older files.
// The caller owns directory permissions and must close the writer after use.
func Open(path string, limit int64, backups int) (*Writer, error) {
	if limit <= 0 || backups < 0 || backups > 16 {
		return nil, errors.New("invalid log retention limits")
	}
	w := &Writer{path: path, limit: limit, backups: backups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func regularLog(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("process log must be a regular file")
	}
	return info, nil
}

func (w *Writer) open() (failure error) {
	named, err := regularLog(w.path)
	if errors.Is(err, os.ErrNotExist) {
		f, createErr := os.OpenFile(w.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if createErr != nil {
			return createErr
		}
		w.file, w.size = f, 0
		return nil
	}
	if err != nil {
		return err
	}
	source, err := os.OpenFile(w.path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() {
		if source != nil {
			failure = errors.Join(failure, source.Close())
		}
	}()
	opened, err := source.Stat()
	if err != nil {
		return err
	}
	if !sameLog(named, opened) {
		return errors.New("process log changed before opening")
	}
	if opened.Size() > w.limit {
		closeErr := source.Close()
		source = nil
		if closeErr != nil {
			return closeErr
		}
		return w.retainTail(opened)
	}
	if _, err = source.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	w.file, w.size = source, opened.Size()
	source = nil
	return nil
}

func sameLog(want, got os.FileInfo) bool {
	return got.Mode().IsRegular() && os.SameFile(want, got) &&
		want.Size() == got.Size() && want.ModTime().Equal(got.ModTime())
}

// retainTail publishes a private same-directory copy after its bytes are
// written and synced.
func (w *Writer) retainTail(original os.FileInfo) (failure error) {
	source, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer func() {
		if source != nil {
			failure = errors.Join(failure, source.Close())
		}
	}()
	opened, err := source.Stat()
	if err != nil {
		return err
	}
	if !sameLog(original, opened) {
		return errors.New("process log changed before retaining its tail")
	}
	stage, err := os.CreateTemp(filepath.Dir(w.path), ".log-tail-*")
	if err != nil {
		return err
	}
	stagePath := stage.Name()
	defer func() {
		if stage != nil {
			failure = errors.Join(failure, stage.Close())
		}
		if stagePath != "" {
			failure = errors.Join(failure, os.Remove(stagePath))
		}
	}()
	tail := io.NewSectionReader(source, original.Size()-w.limit, w.limit)
	written, err := io.CopyBuffer(stage, tail, make([]byte, 32<<10))
	if err != nil {
		return err
	}
	if written != w.limit {
		return io.ErrUnexpectedEOF
	}
	// Windows denies rename of this file while our read handle is open.
	closeErr := source.Close()
	source = nil
	if closeErr != nil {
		return closeErr
	}
	if err := stage.Sync(); err != nil {
		return err
	}
	stagedInfo, err := stage.Stat()
	if err != nil {
		return err
	}
	closeErr = stage.Close()
	stage = nil
	if closeErr != nil {
		return closeErr
	}
	if err := verifyNamedLog(w.path, original); err != nil {
		return err
	}
	if err := verifyNamedLog(stagePath, stagedInfo); err != nil {
		return err
	}
	if err := os.Rename(stagePath, w.path); err != nil {
		return err
	}
	stagePath = ""
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	opened, err = f.Stat()
	if err != nil || !sameLog(stagedInfo, opened) {
		return errors.Join(errors.New("retained process log could not be verified"), err, f.Close())
	}
	w.file, w.size = f, opened.Size()
	return nil
}

func verifyNamedLog(path string, expected os.FileInfo) error {
	named, err := regularLog(path)
	if err != nil {
		return err
	}
	if !sameLog(expected, named) {
		return errors.New("process log changed before replacement")
	}
	return nil
}

func (w *Writer) rotate() error {
	current, err := w.file.Stat()
	if err != nil {
		return err
	}
	if err := verifyNamedLog(w.path, current); err != nil {
		return err
	}
	for i := 1; i <= w.backups; i++ {
		if _, err := regularLog(w.path + "." + strconv.Itoa(i)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	closeErr := w.file.Close()
	w.file = nil
	if closeErr != nil {
		return closeErr
	}
	if w.backups == 0 {
		if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		if err := os.Remove(w.path + "." + strconv.Itoa(w.backups)); err != nil && !os.IsNotExist(err) {
			return err
		}
		for i := w.backups - 1; i >= 1; i-- {
			if err := os.Rename(w.path+"."+strconv.Itoa(i), w.path+"."+strconv.Itoa(i+1)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return w.open()
}

func (w *Writer) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(data) > 0 {
		if w.size >= w.limit {
			if err := w.rotate(); err != nil {
				w.err = fmt.Errorf("rotate process log: %w", err)
				return written, w.err
			}
		}
		next := int64(len(data))
		if available := w.limit - w.size; next > available {
			next = available
		}
		n, err := w.file.Write(data[:int(next)])
		written += n
		w.size += int64(n)
		data = data[n:]
		if n == 0 && err == nil {
			err = io.ErrShortWrite
		}
		if err != nil {
			w.err = err
			return written, err
		}
	}
	return written, nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		w.closed = true
		if w.file != nil {
			w.err = errors.Join(w.err, w.file.Close())
		}
	}
	// Preserve an earlier write/rotation failure even if closing succeeds. A
	// caller completing an operation must not report successful log retention
	// after output was lost. Repeated closes retain the same failure outcome.
	return w.err
}
