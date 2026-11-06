package engine

import (
	"context"
	"errors"
	"io"
	"sync"
)

var errPreparationCanceled = errors.New("launch preparation canceled; generated files may remain")
var errPreparationContextRequired = errors.New("launch preparation requires a context")

type preparationCancellation struct{ cause error }

func (e *preparationCancellation) Error() string   { return errPreparationCanceled.Error() }
func (e *preparationCancellation) Unwrap() []error { return []error{errPreparationCanceled, e.cause} }

func preparationContextError(ctx context.Context, causes ...error) error {
	if ctx == nil {
		return errPreparationContextRequired
	}
	if err := ctx.Err(); err != nil {
		return &preparationCancellation{cause: errors.Join(append([]error{err}, causes...)...)}
	}
	return nil
}

// Cancellation is checked around synchronous reads, never by abandoning an I/O
// goroutine. A native read/Close already in progress must still return. Wrapping
// also prevents io.Copy from bypassing checks through a file's WriterTo method.
type preparationReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r preparationReader) Read(p []byte) (int, error) {
	if err := preparationContextError(r.ctx); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if canceled := preparationContextError(r.ctx, err); canceled != nil {
		return n, canceled
	}
	return n, err
}

// The zero value serializes the same operations as the former mutex. Only
// launch admission is cancelable; accepted stop/shutdown cleanup keeps waiting.
type operationMutex struct {
	once sync.Once
	held chan struct{}
}

func (m *operationMutex) init()   { m.once.Do(func() { m.held = make(chan struct{}, 1) }) }
func (m *operationMutex) Lock()   { m.init(); m.held <- struct{}{} }
func (m *operationMutex) Unlock() { <-m.held }
func (m *operationMutex) LockContext(ctx context.Context) error {
	if err := preparationContextError(ctx); err != nil {
		return err
	}
	m.init()
	select {
	case <-ctx.Done():
		return preparationContextError(ctx)
	case m.held <- struct{}{}:
		if err := preparationContextError(ctx); err != nil {
			m.Unlock()
			return err
		}
		return nil
	}
}
