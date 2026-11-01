// Package logfile bounds persistent child-process logs by rotating fixed-size files.
package logfile

import (
	"errors"
	"fmt"
	"io"
	"os"
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

func (w *Writer) open() error {
	if info, err := os.Lstat(w.path); err == nil && !info.Mode().IsRegular() {
		return errors.New("process log must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.file, w.size = f, info.Size()
	if w.size > w.limit {
		// Keep the most recent bytes when upgrading an older unbounded log.
		previous, err := os.Open(w.path)
		if err != nil {
			_ = f.Close()
			return err
		}
		tail := make([]byte, int(w.limit))
		_, err = previous.ReadAt(tail, w.size-w.limit)
		_ = previous.Close()
		if err == nil {
			err = f.Truncate(0)
		}
		if err == nil {
			_, err = f.Seek(0, io.SeekStart)
		}
		if err == nil {
			_, err = f.Write(tail)
		}
		if err != nil {
			_ = f.Close()
			return err
		}
		w.size = w.limit
	}
	if _, err = f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return err
	}
	return nil
}

func (w *Writer) rotate() error {
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
		w.file = nil
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
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
