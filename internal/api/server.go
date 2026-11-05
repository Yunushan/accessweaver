package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/diagnostics"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/uiaccess"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

type Server struct {
	Policy       *managed.Guard
	Store        *profile.Store
	Manager      *engine.Manager
	Workflows    *workflow.Manager
	UI           fs.FS
	Token        string
	profileAudit *audit.Recorder
	mutations    mutationGate
	historyRead  sync.Mutex
	statusRead   sync.Mutex
	lifecycleMu  sync.Mutex
	shutdown     *serverShutdownState
}

func New(store *profile.Store, manager *engine.Manager, static fs.FS) (*Server, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{Policy: managed.NewGuard(nil), Store: store, Manager: manager, Workflows: workflow.New(store.Root), UI: static, Token: base64.RawURLEncoding.EncodeToString(b)}, nil
}
func JSON(w http.ResponseWriter, status int, v any) {
	// Encode before committing a success status so serialization errors can
	// return valid generic JSON without private error details.
	body, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":"response encoding failed"}`)
	}
	body = append(body, '\n')
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
func fail(w http.ResponseWriter, status int, message string) {
	JSON(w, status, map[string]string{"error": message})
}

func failProfile(w http.ResponseWriter, err error, fallback int) {
	status := fallback
	if errors.Is(err, audit.ErrRecorderUnavailable) || errors.Is(err, audit.ErrRecordedUncertain) {
		fail(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if errors.Is(err, profile.ErrConflict) {
		status = http.StatusConflict
	}
	if errors.Is(err, managed.ErrDenied) {
		status = http.StatusForbidden
	}
	if errors.Is(err, managed.ErrUnavailable) {
		status = http.StatusServiceUnavailable
	}
	if errors.Is(err, profile.ErrStoreBusy) {
		status = http.StatusServiceUnavailable
		w.Header().Set("Retry-After", "1")
	}
	fail(w, status, err.Error())
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/support", s.support)
	s.workflowRoutes(mux)
	mux.HandleFunc("GET /api/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, 200, map[string]any{"version": buildinfo.Version, "platform": runtime.GOOS, "arch": runtime.GOARCH, "build": buildinfo.Current(), "profileEditingOnly": s.profileAudit != nil})
	})
	mux.HandleFunc("GET /api/v1/engines", func(w http.ResponseWriter, r *http.Request) { JSON(w, 200, engine.Catalog()) })
	mux.HandleFunc("GET /api/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Store.ListContext(r.Context())
		if err != nil {
			failProfile(w, err, 500)
			return
		}
		JSON(w, 200, p)
	})
	mux.HandleFunc("GET /api/v1/profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Store.GetContext(r.Context(), r.PathValue("id"))
		if err != nil {
			failProfile(w, err, 404)
			return
		}
		JSON(w, 200, p)
	})
	mux.HandleFunc("PUT /api/v1/profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		var p profile.Profile
		if err := readJSON(w, r, &p); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if r.PathValue("id") != p.ID {
			fail(w, 400, "profile ID must match URL")
			return
		}
		if state := s.Manager.Snapshot(); state.State == "running" && state.ProfileID == p.ID {
			fail(w, 409, "stop active profile before editing")
			return
		}
		if err := s.profileChange(r.Context(), "profile.write", func(ctx context.Context) error { return s.Store.SaveIfUnchangedContext(ctx, p) }); err != nil {
			failProfile(w, err, http.StatusBadRequest)
			return
		}
		got, err := s.Store.GetContext(r.Context(), p.ID)
		if err != nil {
			failProfile(w, err, 500)
			return
		}
		JSON(w, 200, got)
	})
	mux.HandleFunc("DELETE /api/v1/profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var input struct {
			ExpectedUpdatedAt time.Time `json:"expectedUpdatedAt"`
		}
		if err := readJSON(w, r, &input); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if input.ExpectedUpdatedAt.IsZero() {
			fail(w, 400, "send the reviewed profile's expectedUpdatedAt revision before deleting")
			return
		}
		if state := s.Manager.Snapshot(); state.State == "running" && state.ProfileID == id {
			fail(w, 409, "stop active profile before deleting")
			return
		}
		if err := s.profileChange(r.Context(), "profile.delete", func(ctx context.Context) error {
			return s.Store.DeleteIfUnchangedContext(ctx, id, input.ExpectedUpdatedAt)
		}); err != nil {
			failProfile(w, err, http.StatusBadRequest)
			return
		}
		JSON(w, 200, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("GET /api/v1/runtime", func(w http.ResponseWriter, r *http.Request) { JSON(w, 200, s.Manager.Snapshot()) })
	mux.HandleFunc("POST /api/v1/preview", func(w http.ResponseWriter, r *http.Request) {
		var p profile.Profile
		if err := readJSON(w, r, &p); err != nil {
			fail(w, 400, err.Error())
			return
		}
		plan, err := s.Manager.Preview(p)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		JSON(w, 200, plan)
	})
	mux.HandleFunc("POST /api/v1/start", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID                string `json:"id"`
			Confirm           bool   `json:"confirm"`
			ExpectedUpdatedAt string `json:"expectedUpdatedAt"`
		}
		if err := readJSON(w, r, &req); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if !req.Confirm {
			fail(w, 400, "explicit confirmation required")
			return
		}
		p, err := s.Store.GetContext(r.Context(), req.ID)
		if err != nil {
			failProfile(w, err, 404)
			return
		}
		if req.ExpectedUpdatedAt == "" {
			fail(w, 400, "review the saved profile and send its expectedUpdatedAt revision before starting")
			return
		}
		if req.ExpectedUpdatedAt != p.UpdatedAt.Format(time.RFC3339Nano) {
			fail(w, 409, "profile changed since launch review; reopen the launch preview")
			return
		}
		if err := s.Manager.Start(p); err != nil {
			failProfile(w, err, http.StatusBadRequest)
			return
		}
		JSON(w, 200, s.Manager.Snapshot())
	})
	mux.HandleFunc("POST /api/v1/stop", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Manager.Stop(); err != nil {
			fail(w, 500, err.Error())
			return
		}
		JSON(w, 200, s.Manager.Snapshot())
	})
	mux.HandleFunc("POST /api/v1/diagnose", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Policy.Diagnostics(); err != nil {
			fail(w, http.StatusForbidden, err.Error())
			return
		}
		var input diagnostics.Request
		if err := readJSON(w, r, &input); err != nil {
			fail(w, 400, err.Error())
			return
		}
		report, err := diagnostics.Diagnose(r.Context(), input, s.Policy)
		if err != nil {
			status := http.StatusRequestTimeout
			if managed.IsPolicyError(err) {
				status = http.StatusForbidden
			}
			fail(w, status, err.Error())
			return
		}
		JSON(w, 200, report)
	})
	fileServer := http.FileServer(http.FS(s.UI))
	mux.Handle("/", fileServer)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject DNS rebinding/host-header attacks. Only use via loopback.
		host := r.Host
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = host
		}
		if hostname != "127.0.0.1" && hostname != "localhost" && hostname != "[::1]" && hostname != "::1" {
			fail(w, 403, "loopback host required")
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// Browser metadata protects reads as well as writes; local CLI clients
			// do not send these headers and still require a token for mutations.
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				fail(w, 403, "cross-origin request denied")
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				parsed, e := url.Parse(o)
				if e != nil || parsed.Host != r.Host || parsed.Scheme != "http" {
					fail(w, 403, "cross-origin request denied")
					return
				}
			}
			// Reads contain private profiles/history too. Bootstrap cannot disclose
			// the credential: the OS-private browser launcher delivers it instead.
			if s.Token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-AccessWeaver-Token")), []byte(s.Token)) != 1 {
				fail(w, 403, "missing or invalid session token; open the private browser launch file")
				return
			}
			if !s.profileAuditAllows(r) {
				fail(w, http.StatusForbidden, "this desktop session supports profile editing and previews only")
				return
			}
			if r.Method != "GET" && r.Method != "HEAD" {
				if r.Header.Get("Content-Type") != "" && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
					fail(w, 415, "JSON content type required")
					return
				}
				if r.ContentLength > maxAPIRequestBodyBytes {
					fail(w, 413, "payload too large")
					return
				}
				// Keep active-profile checks and mutations in one transaction.
				// Diagnostics and read-only previews need not serialize with these.
				if r.URL.Path != "/api/v1/diagnose" && r.URL.Path != "/api/v1/preview" {
					releaseAdmission, err := s.mutations.reserve(r.Context())
					if err != nil {
						rejectMutation(w, err)
						return
					}
					defer releaseAdmission()
					if err := prepareMutationBody(w, r); err != nil {
						rejectMutation(w, err)
						return
					}
					release, err := s.mutations.acquire(r.Context())
					if err != nil {
						rejectMutation(w, err)
						return
					}
					defer release()
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBodyBytes)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected one JSON object")
	}

	return nil
}

// serverShutdownState publishes its result before done closes. Pending is only
// a diagnostic observation; it never substitutes for owned completion.
type serverShutdownState struct {
	done        chan struct{}
	pending     chan struct{}
	pendingOnce sync.Once
	err         error
}

func (s *serverShutdownState) markPending() {
	s.pendingOnce.Do(func() { close(s.pending) })
}

// Admission closes under the same mutex as Add, before any counter wait. Late
// requests cannot enter profile, workflow or engine handlers during shutdown.
type serverHandlerGate struct {
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

func (g *serverHandlerGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			fail(w, http.StatusServiceUnavailable, "desktop shutdown in progress")
			return
		}
		g.active.Add(1)
		g.mu.Unlock()
		defer g.active.Done()
		next.ServeHTTP(w, r)
	})
}
func (g *serverHandlerGate) closeAdmission() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}
func (g *serverHandlerGate) wait() { g.active.Wait() }

// The first context bounds only a diagnostic wait. Both calls observe the same
// Manager shutdown worker; the background join cannot repeat Stop or cleanup.
func waitServerEngineShutdown(initial context.Context, shutdown func(context.Context) error, pendingFault func() bool, pending func()) error {
	if pendingFault() {
		pending()
	}
	initialErr := shutdown(initial)
	if initial.Err() != nil && errors.Is(initialErr, initial.Err()) {
		pending()
	}
	return shutdown(context.Background())
}

func (s *Server) Serve(ctx context.Context) (string, error) {
	if err := uiaccess.RequireUnelevated(); err != nil {
		return "", err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	return s.serveListener(ctx, listener)
}

// serveListener takes ownership of this already-created loopback listener. The
// public Serve path always performs the native unelevated admission first.
func (s *Server) serveListener(ctx context.Context, listener net.Listener) (string, error) {
	s.lifecycleMu.Lock()
	if s.shutdown != nil {
		s.lifecycleMu.Unlock()
		return "", errors.Join(errors.New("desktop server already started"), listener.Close())
	}
	state := &serverShutdownState{done: make(chan struct{}), pending: make(chan struct{})}
	s.shutdown = state
	s.lifecycleMu.Unlock()
	addr := "http://" + listener.Addr().String()
	gate := &serverHandlerGate{}
	server := &http.Server{Handler: gate.wrap(s.Handler()), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 75 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	lifetime, cancelLifetime := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() {
		served <- server.Serve(listener)
		cancelLifetime()
	}()
	go func() {
		defer close(state.done)
		defer cancelLifetime()
		<-lifetime.Done()
		gate.closeAdmission()
		// Start engine ownership shutdown before waiting for HTTP handlers: an
		// admitted start/stop request must not prevent manager closing or drain.
		engineDone := make(chan error, 1)
		go func() {
			engineContext, cancelEngine := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancelEngine()
			engineDone <- waitServerEngineShutdown(engineContext, s.Manager.Shutdown, func() bool { return s.Manager.Snapshot().LifecyclePending }, state.markPending)
		}()
		s.Workflows.Cancel()
		httpContext, cancelHTTP := context.WithTimeout(context.Background(), 5*time.Second)
		httpErr := server.Shutdown(httpContext)
		if httpErr != nil {
			state.markPending()
			httpErr = errors.Join(httpErr, server.Close())
		}
		cancelHTTP()
		workflowContext, cancelWorkflow := context.WithTimeout(context.Background(), 8*time.Second)
		// Workflow/vendor lifetime recovery remains a separate boundary. Retain
		// its existing bounded wait; do not claim it proves full workflow cleanup.
		_ = s.Workflows.Shutdown(workflowContext)
		cancelWorkflow()
		gate.wait()
		serveErr := <-served
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		state.err = errors.Join(httpErr, serveErr, <-engineDone)
	}()
	return addr, nil
}

func (s *Server) shutdownState() *serverShutdownState {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.shutdown
}

// Done closes only after admitted handlers, HTTP serving and the exact engine
// shutdown worker have finished. A caller timeout cannot close this channel.
func (s *Server) Done() <-chan struct{} {
	if state := s.shutdownState(); state != nil {
		return state.done
	}
	return nil
}

// ShutdownPending reports one observed unresolved desktop shutdown after an HTTP
// shutdown error, fixed engine fault or engine diagnostic budget. Done may race
// it and remains the terminal proof.
func (s *Server) ShutdownPending() <-chan struct{} {
	if state := s.shutdownState(); state != nil {
		return state.pending
	}
	return nil
}

// Wait retains the whole server scope until owned completion and returns its
// stored final error. Before Serve starts there is no owned scope to drain.
func (s *Server) Wait() error {
	if state := s.shutdownState(); state != nil {
		<-state.done
		return state.err
	}
	return nil
}
