package api

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Yunushan/accessweaver/internal/engine"
)

func awaitServerShutdown(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(message)
	}
}

// This is the server's composition protocol, not a fake engine or native fault
// claim. Engine tests independently qualify its real shared shutdown worker.
func TestServerEngineShutdownRetainsBackgroundCompletionAndFinalError(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(map[bool]string{false: "diagnostic-budget", true: "already-pending-fault"}[fault], func(t *testing.T) {
			state := &serverShutdownState{done: make(chan struct{}), pending: make(chan struct{})}
			server := &Server{shutdown: state}
			complete, first, background, returned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			initial, cancel := context.WithCancel(context.Background())
			var release sync.Once
			t.Cleanup(func() {
				cancel()
				release.Do(func() { close(complete) })
				awaitServerShutdown(t, returned, "server shutdown fixture did not drain")
			})
			stopErr := errors.New("retained stop result")
			finalErr := errors.Join(stopErr, engine.ErrProcessLifecycle)
			var calls atomic.Int32
			shutdown := func(ctx context.Context) error {
				if calls.Add(1) == 1 {
					close(first)
				} else {
					if ctx.Err() != nil || ctx.Done() != nil {
						t.Error("server final shutdown join retained caller cancellation")
					}
					close(background)
				}
				select {
				case <-complete:
					return finalErr
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			go func() {
				defer close(returned)
				state.err = waitServerEngineShutdown(initial, shutdown, func() bool { return fault }, state.markPending)
				close(state.done)
			}()
			awaitServerShutdown(t, first, "server initial shutdown was not started")
			if !fault {
				cancel()
				awaitServerShutdown(t, background, "server did not join shared shutdown in background")
			}
			awaitServerShutdown(t, server.ShutdownPending(), "server unresolved shutdown was silent")
			select {
			case <-server.Done():
				t.Fatal("diagnostic budget or pending fault fabricated server completion")
			default:
			}
			release.Do(func() { close(complete) })
			awaitServerShutdown(t, server.Done(), "server did not observe actual shutdown completion")
			for i := 0; i < 2; i++ {
				if err := server.Wait(); !errors.Is(err, stopErr) || !errors.Is(err, engine.ErrProcessLifecycle) || errors.Is(err, context.Canceled) {
					t.Fatal("server lost terminal shutdown result or retained diagnostic cancellation")
				}
			}
			if calls.Load() != 2 {
				t.Fatal("server repeated a shutdown join or skipped the shared final result")
			}
		})
	}
}

func TestServerEngineTerminalErrorDoesNotFabricatePending(t *testing.T) {
	pending := 0
	failure := engine.ErrProcessLifecycle
	err := waitServerEngineShutdown(context.Background(), func(context.Context) error { return failure }, func() bool { return false }, func() { pending++ })
	if !errors.Is(err, failure) || pending != 0 {
		t.Fatal("completed lifecycle uncertainty was lost or called pending")
	}
}

func TestServerHandlerAdmissionClosesBeforeCounterWait(t *testing.T) {
	gate := &serverHandlerGate{}
	entered, release, returned, drained := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		awaitServerShutdown(t, returned, "admitted handler fixture did not return")
		awaitServerShutdown(t, drained, "handler counter fixture did not drain")
	})
	var admitted atomic.Int32
	handler := gate.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		admitted.Add(1)
		close(entered)
		<-release
	}))
	go func() {
		defer close(returned)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://127.0.0.1/", nil))
	}()
	awaitServerShutdown(t, entered, "owned handler did not enter admission")
	gate.closeAdmission()
	go func() { gate.wait(); close(drained) }()
	late := httptest.NewRecorder()
	handler.ServeHTTP(late, httptest.NewRequest("GET", "http://127.0.0.1/", nil))
	if late.Code != http.StatusServiceUnavailable || admitted.Load() != 1 {
		t.Fatal("closed server admitted a replacement handler")
	}
	select {
	case <-drained:
		t.Fatal("handler counter returned before admitted work")
	default:
	}
	once.Do(func() { close(release) })
	awaitServerShutdown(t, drained, "handler wait held the admission mutex")
}

type shutdownBlockingFS struct {
	base             fs.FS
	entered, release chan struct{}
	once             sync.Once
}

func (s *shutdownBlockingFS) Open(name string) (fs.File, error) {
	s.once.Do(func() { close(s.entered); <-s.release })
	return s.base.Open(name)
}

func TestServerWaitRetainsAdmittedHTTPHandlerAfterEngineShutdown(t *testing.T) {
	for _, exhaustBudget := range []bool{false, true} {
		t.Run(map[bool]string{false: "handler-completes", true: "http-budget-expired"}[exhaustBudget], func(t *testing.T) {
			server := makeServer(t)
			files := &shutdownBlockingFS{base: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("owned handler complete")}}, entered: make(chan struct{}), release: make(chan struct{})}
			server.UI = files
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("server loopback fixture listener unavailable")
			}
			ctx, cancel := context.WithCancel(context.Background())
			var release sync.Once
			client := &http.Client{Timeout: 10 * time.Second}
			requestDone := make(chan struct{})
			var requestErr error
			t.Cleanup(func() {
				cancel()
				release.Do(func() { close(files.release) })
				client.CloseIdleConnections()
				awaitServerShutdown(t, requestDone, "HTTP shutdown fixture request did not finish")
				if server.Done() != nil {
					awaitServerShutdown(t, server.Done(), "HTTP shutdown fixture server did not finish")
				}
			})
			addr, err := server.serveListener(ctx, listener)
			if err != nil {
				close(requestDone)
				t.Fatal("owned server fixture did not start")
			}
			originalDone := server.Done()
			go func() {
				defer close(requestDone)
				response, err := client.Get(addr + "/")
				if err != nil {
					requestErr = err
					return
				}
				data, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
				closeErr := response.Body.Close()
				if response.StatusCode != http.StatusOK || string(data) != "owned handler complete" || readErr != nil || closeErr != nil {
					requestErr = errors.New("owned response was not completed")
				}
			}()
			awaitServerShutdown(t, files.entered, "HTTP handler fixture did not enter")
			cancel()
			// Joining the completed no-engine worker cannot release the still
			// admitted HTTP handler or create another native shutdown attempt.
			if server.Manager.Shutdown(context.Background()) != nil {
				t.Fatal("empty engine shutdown failed")
			}
			if exhaustBudget {
				// Use the actual unchanged five-second HTTP budget. No timer or
				// canceled connection is accepted as handler-completion proof.
				select {
				case <-server.ShutdownPending():
				case <-time.After(8 * time.Second):
					t.Fatal("HTTP shutdown budget expired without fixed pending feedback")
				}
			}
			select {
			case <-originalDone:
				t.Fatal("server completed while an admitted HTTP handler was still active")
			default:
			}
			release.Do(func() { close(files.release) })
			awaitServerShutdown(t, originalDone, "server did not finish after owned handler returned")
			awaitServerShutdown(t, requestDone, "owned HTTP response did not finish")
			terminal := server.Wait()
			if server.Wait() != terminal || server.Done() != originalDone {
				t.Fatal("server final completion was not retained")
			}
			if exhaustBudget {
				if !errors.Is(terminal, context.DeadlineExceeded) {
					t.Fatal("server lost its actual HTTP shutdown budget error")
				}
				// Close may cancel the response, or the release can race it. The
				// owned handler and client are both joined either way.
			} else {
				if requestErr != nil || terminal != nil {
					t.Fatal("server final completion or response was not retained")
				}
				select {
				case <-server.ShutdownPending():
					t.Fatal("empty engine shutdown was called pending")
				default:
				}
			}
		})
	}
}
func TestServerEmptyShutdownAndNoRebind(t *testing.T) {
	server := makeServer(t)
	server.UI = fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("fixture")}}
	if server.Done() != nil || server.ShutdownPending() != nil || server.Wait() != nil {
		t.Fatal("unstarted server fabricated a shutdown scope")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("empty server listener unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if _, err := server.serveListener(ctx, listener); err != nil {
		t.Fatal("empty server did not start")
	}
	cancel()
	awaitServerShutdown(t, server.Done(), "no-engine shutdown did not finish quickly")
	if server.Wait() != nil {
		t.Fatal("empty server shutdown failed")
	}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("rebind fixture listener unavailable")
	}
	secondContext, cancelSecond := context.WithCancel(context.Background())
	t.Cleanup(cancelSecond)
	if tcp, ok := second.(*net.TCPListener); ok {
		_ = tcp.SetDeadline(time.Now().Add(time.Second))
	}
	if _, err := server.serveListener(secondContext, second); err == nil {
		t.Fatal("completed server rebound its shutdown state")
	}
	if _, err := second.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("refused server rebind retained its listener")
	}
}

type shutdownFailedListener struct {
	failure error
	closed  chan struct{}
	once    sync.Once
}

func (l *shutdownFailedListener) Accept() (net.Conn, error) { return nil, l.failure }
func (l *shutdownFailedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}
func (l *shutdownFailedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestServerUnexpectedServeErrorTriggersOwnedShutdown(t *testing.T) {
	server := makeServer(t)
	server.UI = fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("fixture")}}
	failure := errors.New("controlled listener failure")
	listener := &shutdownFailedListener{failure: failure, closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if _, err := server.serveListener(ctx, listener); err != nil {
		t.Fatal("listener error fixture did not enter serving")
	}
	awaitServerShutdown(t, server.Done(), "unexpected listener failure waited for external cancellation")
	if ctx.Err() != nil || !errors.Is(server.Wait(), failure) {
		t.Fatal("internal HTTP failure was not retained independently of caller context")
	}
	awaitServerShutdown(t, listener.closed, "failed HTTP listener was not closed")
}
