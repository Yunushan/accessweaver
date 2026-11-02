package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type heldHistoryResponse struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *heldHistoryResponse) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.ResponseRecorder.Write(b)
}

func TestHistoryAdmissionCoversResponseAndKeepsControlsAvailable(t *testing.T) {
	s := makeServer(t)
	response := &heldHistoryResponse{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(response.release) }) }
	defer release()
	done := make(chan struct{})
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system/history", nil)
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	go func() {
		defer close(done)
		s.Handler().ServeHTTP(response, r)
	}()
	select {
	case <-response.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first history response did not start")
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := request(t, s, method, "/api/v1/system/history", nil, s.Token, "127.0.0.1")
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
			t.Fatalf("overlapping %s history response: %d, retry %q", method, w.Code, w.Header().Get("Retry-After"))
		}
	}
	for _, check := range []struct {
		method, path, token string
		status              int
	}{
		{http.MethodGet, "/api/v1/system/history", "wrong", http.StatusForbidden},
		{http.MethodGet, "/api/bootstrap", s.Token, http.StatusOK},
		{http.MethodGet, "/api/v1/system", s.Token, http.StatusOK},
		{http.MethodPost, "/api/v1/system/cancel", s.Token, http.StatusOK},
	} {
		w := request(t, s, check.method, check.path, nil, check.token, "127.0.0.1")
		if w.Code != check.status {
			t.Fatalf("control %s: %d", check.path, w.Code)
		}
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("history did not finish")
	}
	if response.Code != http.StatusOK || response.Body.String() != "[]\n" {
		t.Fatal("first history response changed")
	}
	w := request(t, s, http.MethodGet, "/api/v1/system/history", nil, s.Token, "127.0.0.1")
	if w.Code != http.StatusOK || w.Body.String() != "[]\n" {
		t.Fatalf("history admission did not recover: %d", w.Code)
	}
}

func TestEndedHistoryRequestAndDiskFailureReleaseAdmission(t *testing.T) {
	s := makeServer(t)
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if expired {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			cancel()
		}
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system/history", nil).WithContext(ctx)
		r.Header.Set("X-AccessWeaver-Token", s.Token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		cancel()
		if w.Code != http.StatusRequestTimeout {
			t.Fatalf("ended history: %d", w.Code)
		}
	}
	// A file at the directory name makes the real scan fail, not a fake loader.
	path := filepath.Join(s.Store.Root, "workflows")
	if err := os.WriteFile(path, []byte("retained fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		w := request(t, s, http.MethodGet, "/api/v1/system/history", nil, s.Token, "127.0.0.1")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("disk error left admission busy: %d", w.Code)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, http.MethodGet, "/api/v1/system/history", nil, s.Token, "127.0.0.1")
	if w.Code != http.StatusOK {
		t.Fatalf("history did not recover: %d", w.Code)
	}
}

type failedHistoryResponse struct{ *httptest.ResponseRecorder }

func (w failedHistoryResponse) Write([]byte) (int, error) {
	return 0, errors.New("disconnected history reader")
}

func TestFailedHistoryResponseReleasesAdmission(t *testing.T) {
	s := makeServer(t)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system/history", nil)
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	func() {
		defer func() {
			if recovered := recover(); recovered != http.ErrAbortHandler {
				t.Fatalf("failed stream did not abort HTTP framing: %v", recovered)
			}
		}()
		s.Handler().ServeHTTP(failedHistoryResponse{httptest.NewRecorder()}, r)
	}()
	w := request(t, s, http.MethodGet, "/api/v1/system/history", nil, s.Token, "127.0.0.1")
	if w.Code != http.StatusOK {
		t.Fatalf("write failure retained admission: %d", w.Code)
	}
}
