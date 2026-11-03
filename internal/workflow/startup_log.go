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
	})
	if w.timingErr != nil {
		return 0, w.timingErr
	}
	return w.writer.Write(data)
}
