package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

// These are private server-composition tests. The controlled operation is not a
// native workflow or vendor-cleanup claim; workflow package fixtures separately
// exercise the real manager's reserved generation and persistence lifetime.
func TestServerWorkflowDiagnosticBudgetRetainsAuthoritativeCompletion(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "terminal-error"}[failed], func(t *testing.T) {
			initial, cancel := context.WithCancel(context.Background())
			first, background, complete, returned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			state := &serverShutdownState{pending: make(chan struct{})}
			var release sync.Once
			t.Cleanup(func() {
				cancel()
				release.Do(func() { close(complete) })
				awaitServerShutdown(t, returned, "workflow composition fixture did not drain")
			})
			var terminal error
			if failed {
				terminal = errors.New("controlled workflow terminal result")
			}
			var calls atomic.Int32
			shutdown := func(ctx context.Context) error {
				switch calls.Add(1) {
				case 1:
					close(first)
				case 2:
					if ctx.Err() != nil || ctx.Done() != nil {
						t.Error("workflow final join retained diagnostic cancellation")
					}
					close(background)
				default:
					t.Error("server repeated workflow completion joins")
				}
				select {
				case <-complete:
					return terminal
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			var result error
			go func() {
				defer close(returned)
				result = waitServerWorkflowShutdown(initial, shutdown, state.markPending)
			}()
			awaitServerShutdown(t, first, "workflow diagnostic wait did not start")
			cancel()
			awaitServerShutdown(t, background, "workflow completion was not joined in background")
			awaitServerShutdown(t, state.pending, "workflow diagnostic timeout was silent")
			select {
			case <-returned:
				t.Fatal("diagnostic timeout substituted for workflow completion")
			default:
			}
			release.Do(func() { close(complete) })
			awaitServerShutdown(t, returned, "workflow completion did not release server join")
			if result != terminal || errors.Is(result, context.Canceled) || calls.Load() != 2 {
				t.Fatal("workflow authoritative result was lost or diagnostic cancellation retained")
			}
		})
	}
}

func TestServerCompletedWorkflowErrorDoesNotFabricatePending(t *testing.T) {
	terminal := errors.New("completed workflow terminal result")
	for _, failed := range []bool{false, true} {
		var result error
		if failed {
			result = terminal
		}
		calls, pending := 0, 0
		err := waitServerWorkflowShutdown(context.Background(), func(context.Context) error {
			calls++
			return result
		}, func() { pending++ })
		if err != result || calls != 2 || pending != 0 {
			t.Fatal("completed workflow result skipped final join or fabricated pending")
		}
	}
}

type workflowShutdownListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *workflowShutdownListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func TestServerWaitRetainsWorkflowAfterHTTPAndEngineShutdown(t *testing.T) {
	server := makeServer(t)
	files := &shutdownBlockingFS{base: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("workflow shutdown fixture")}}, entered: make(chan struct{}), release: make(chan struct{})}
	server.UI = files
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("workflow server listener unavailable")
	}
	ownedListener := &workflowShutdownListener{Listener: listener, closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	first, background, complete := make(chan struct{}), make(chan struct{}), make(chan struct{})
	requestDone := make(chan struct{})
	var handlerRelease, workflowRelease sync.Once
	client := &http.Client{Timeout: 12 * time.Second}
	var requestErr error
	requestStarted := false
	t.Cleanup(func() {
		cancel()
		handlerRelease.Do(func() { close(files.release) })
		workflowRelease.Do(func() { close(complete) })
		client.CloseIdleConnections()
		if requestStarted {
			awaitServerShutdown(t, requestDone, "workflow server request did not drain")
		}
		if server.Done() != nil {
			awaitServerShutdown(t, server.Done(), "workflow server scope did not drain")
		} else if err := ownedListener.Close(); err != nil {
			t.Error("unadmitted workflow fixture listener close failed")
		}
	})
	terminal := errors.New("controlled workflow terminal failure")
	var calls atomic.Int32
	shutdown := func(wait context.Context) error {
		switch calls.Add(1) {
		case 1:
			if _, ok := wait.Deadline(); !ok {
				t.Error("workflow diagnostic wait had no budget")
			}
			close(first)
		case 2:
			if wait.Done() != nil || wait.Err() != nil {
				t.Error("workflow background join retained diagnostic budget")
			}
			close(background)
		default:
			t.Error("server repeated workflow shutdown joins")
		}
		select {
		case <-complete:
			return terminal
		case <-wait.Done():
			return wait.Err()
		}
	}
	addr, err := server.serveListenerWithWorkflowShutdown(ctx, ownedListener, shutdown)
	if err != nil {
		t.Fatal("workflow server composition did not start")
	}
	originalDone := server.Done()
	requestStarted = true
	go func() {
		defer close(requestDone)
		response, err := client.Get(addr + "/")
		if err != nil {
			requestErr = err
			return
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK || string(data) != "workflow shutdown fixture" || readErr != nil || closeErr != nil {
			requestErr = errors.New("workflow fixture HTTP response incomplete")
		}
	}()
	awaitServerShutdown(t, files.entered, "workflow fixture HTTP handler did not enter")
	cancel()
	// The first workflow call must begin while this admitted handler is still
	// blocked; HTTP shutdown and handler drain must not defer manager closing.
	awaitServerShutdown(t, first, "workflow shutdown waited for HTTP handler completion")
	if err := server.Manager.Shutdown(context.Background()); err != nil {
		t.Fatal("empty engine manager did not complete shutdown")
	}
	handlerRelease.Do(func() { close(files.release) })
	awaitServerShutdown(t, requestDone, "HTTP handler did not finish before workflow completion")
	awaitServerShutdown(t, ownedListener.closed, "HTTP listener outlived workflow-only wait")
	if requestErr != nil {
		t.Fatal("workflow-only wait did not retain a successful HTTP completion")
	}
	// Exercise the actual unchanged eight-second workflow diagnostic budget.
	// Engine and HTTP work have finished; only the controlled workflow remains.
	select {
	case <-server.ShutdownPending():
	case <-time.After(11 * time.Second):
		t.Fatal("workflow budget expired without fixed pending feedback")
	}
	awaitServerShutdown(t, background, "server abandoned workflow after its diagnostic budget")
	select {
	case <-originalDone:
		t.Fatal("server released scope while workflow completion remained pending")
	default:
	}
	workflowRelease.Do(func() { close(complete) })
	awaitServerShutdown(t, originalDone, "server did not finish after workflow terminal completion")
	final := server.Wait()
	if !errors.Is(final, terminal) || errors.Is(final, context.DeadlineExceeded) || server.Wait() != final || server.Done() != originalDone || calls.Load() != 2 {
		t.Fatal("server lost authoritative workflow error or retained diagnostic timeout")
	}
}
