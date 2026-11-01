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

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/diagnostics"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/uiaccess"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

type Server struct {
	Policy    *managed.Guard
	Store     *profile.Store
	Manager   *engine.Manager
	Workflows *workflow.Manager
	UI        fs.FS
	Token     string
	mutations sync.Mutex
	done      chan struct{}
}

func New(store *profile.Store, manager *engine.Manager, static fs.FS) (*Server, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{Policy: managed.NewGuard(nil), Store: store, Manager: manager, Workflows: workflow.New(store.Root), UI: static, Token: base64.RawURLEncoding.EncodeToString(b)}, nil
}
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	JSON(w, status, map[string]string{"error": message})
}

func failProfile(w http.ResponseWriter, err error, fallback int) {
	status := fallback
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
		JSON(w, 200, map[string]any{"version": buildinfo.Version, "platform": runtime.GOOS, "arch": runtime.GOARCH, "build": buildinfo.Current()})
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
		if err := s.Store.SaveIfUnchangedContext(r.Context(), p); err != nil {
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
		if err := s.Store.DeleteIfUnchangedContext(r.Context(), id, input.ExpectedUpdatedAt); err != nil {
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
		var p profile.Probe
		if err := readJSON(w, r, &p); err != nil {
			fail(w, 400, err.Error())
			return
		}
		JSON(w, 200, diagnostics.Run(r.Context(), p))
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
			if r.Method != "GET" && r.Method != "HEAD" {
				if r.Header.Get("Content-Type") != "" && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
					fail(w, 415, "JSON content type required")
					return
				}
				if r.ContentLength > 1<<20 {
					fail(w, 413, "payload too large")
					return
				}
				// Keep active-profile checks and mutations in one transaction.
				// Diagnostics and read-only previews need not serialize with these.
				if r.URL.Path != "/api/v1/diagnose" && r.URL.Path != "/api/v1/preview" {
					s.mutations.Lock()
					defer s.mutations.Unlock()
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
func (s *Server) Serve(ctx context.Context) (string, error) {
	if err := uiaccess.RequireUnelevated(); err != nil {
		return "", err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := "http://" + listener.Addr().String()
	s.done = make(chan struct{})
	server := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 75 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		defer close(s.done)
		<-ctx.Done()
		s.Workflows.Cancel()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := server.Shutdown(c); err != nil {
			_ = server.Close()
		}
		cancel()
		workflowContext, cancelWorkflow := context.WithTimeout(context.Background(), 8*time.Second)
		_ = s.Workflows.Shutdown(workflowContext)
		cancelWorkflow()
		engineContext, cancelEngine := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancelEngine()
		_ = s.Manager.Shutdown(engineContext)
	}()
	go func() { _ = server.Serve(listener) }()
	return addr, nil
}

// Wait blocks until HTTP and engine shutdown have finished after cancellation.
func (s *Server) Wait() {
	if s.done != nil {
		<-s.done
	}
}
