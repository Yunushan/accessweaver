package workflow

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// startupLog preserves child output while recording when the first bytes arrive.
// The underlying workflow log serializes concurrent stdout/stderr writes.
type startupLog struct {
	writer    io.Writer
	started   time.Time
	once      sync.Once
	timingErr error
	mu        sync.Mutex
	writeErr  error
}

func (w *startupLog) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	w.once.Do(func() {
		prefix := fmt.Sprintf("Workflow timing ms: first-output %d\n", time.Since(w.started).Milliseconds())
		n, err := io.WriteString(w.writer, prefix)
		if err == nil && n != len(prefix) {
			err = io.ErrShortWrite
		}
		w.timingErr = err
		w.recordFailure(err)
	})
	if w.timingErr != nil {
		return 0, w.timingErr
	}
	n, err := w.writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	w.recordFailure(err)
	return n, err
}

// Go Wait can prefer an ExitError to a copy error. Retain the first log failure
// independently so an abnormal exit cannot erase evidence of incomplete output.
func (w *startupLog) recordFailure(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr == nil {
		w.writeErr = err
	}
}
func (w *startupLog) failure() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeErr
}
