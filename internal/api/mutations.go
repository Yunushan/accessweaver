package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
)

const (
	maxPendingMutations    = 16
	maxAPIRequestBodyBytes = 1 << 20
)

var errMutationQueueFull = errors.New("too many pending operations; wait a moment and try again")

// A transaction token never retains request bodies or caller credentials.
// The zero value is usable; every Handler for a Server shares this gate.
type mutationGate struct {
	once    sync.Once
	active  chan struct{}
	pending chan struct{}
}

func (g *mutationGate) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g.initialize()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case g.active <- struct{}{}:
		// Cancellation may race with an available token. Never dispatch an
		// already canceled request merely because select chose that token.
		if err := ctx.Err(); err != nil {
			<-g.active
			return nil, err
		}
		return func() { <-g.active }, nil
	}
}

func (g *mutationGate) initialize() {
	g.once.Do(func() {
		g.active = make(chan struct{}, 1)
		g.pending = make(chan struct{}, maxPendingMutations)
	})
}

// Admission bounds concurrent body preparation, queued requests and active work.
// A full queue is rejected before retaining a potentially large request body.
func (g *mutationGate) reserve(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g.initialize()
	select {
	case g.pending <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-g.pending
			return nil, err
		}
		return func() { <-g.pending }, nil
	default:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errMutationQueueFull
	}
}

func prepareMutationBody(w http.ResponseWriter, r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		return r.Context().Err()
	}
	limited := http.MaxBytesReader(w, r.Body, maxAPIRequestBodyBytes)
	defer limited.Close()
	body, err := io.ReadAll(limited)
	if err != nil {
		if contextErr := r.Context().Err(); contextErr != nil {
			return contextErr
		}
		return err
	}
	// Reaching EOF enables net/http's disconnect watcher before a request waits
	// for the transaction token. The handler receives the same bounded bytes.
	r.Body = io.NopCloser(bytes.NewReader(body))
	return r.Context().Err()
}

func rejectMutation(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errMutationQueueFull):
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusServiceUnavailable, errMutationQueueFull.Error())
	case errors.Is(err, context.DeadlineExceeded):
		fail(w, http.StatusRequestTimeout, "request expired before the operation started")
	case errors.Is(err, context.Canceled):
		fail(w, http.StatusRequestTimeout, "request canceled before the operation started")
	default:
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			fail(w, http.StatusRequestEntityTooLarge, "payload too large")
		} else {
			fail(w, http.StatusBadRequest, "could not read request body")
		}
	}
}
