package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Yunushan/accessweaver/internal/workflow"
	"testing"
	"time"
)

type queueResponse struct {
	http.ResponseWriter
	status int
}

func (w *queueResponse) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func TestCanceledQueuedHTTPMutationDoesNotDispatch(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"without body", "/api/v1/system/cancel", ""},
		{"with body", "/api/v1/system/preview", `{"action":"discover"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := makeServer(t)
			entered := make(chan struct{})
			returned := make(chan int, 1)
			handler := s.Handler()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					close(entered)
					response := &queueResponse{ResponseWriter: w}
					handler.ServeHTTP(response, r)
					returned <- response.status
					return
				}
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			// Keep an earlier transaction active while the HTTP request queues.
			unlock, err := s.mutations.acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			held := true
			release := func() {
				if held {
					unlock()
					held = false
				}
			}
			defer release()
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			uploaded := make(chan error, 1)
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) { uploaded <- info.Err }})
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+tc.path, bytes.NewBufferString(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-AccessWeaver-Token", s.Token)
			if tc.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			clientDone := make(chan error, 1)
			go func() {
				response, err := client.Do(request)
				if response != nil {
					response.Body.Close()
				}
				clientDone <- err
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("HTTP mutation did not reach server")
			}
			select {
			case err := <-uploaded:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("request body was not uploaded")
			}
			cancel()
			canceledPromptly := false
			status := 0
			select {
			case status = <-returned:
				canceledPromptly = true
			case <-time.After(2 * time.Second):
			}
			// Metadata reads remain available while a mutation is active.
			read, err := http.NewRequest(http.MethodGet, server.URL+"/api/bootstrap", nil)
			if err != nil {
				t.Fatal(err)
			}
			read.Header.Set("X-AccessWeaver-Token", s.Token)
			response, err := client.Do(read)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Errorf("metadata read blocked or failed: %d", response.StatusCode)
			}
			release()
			if !canceledPromptly {
				select {
				case status = <-returned:
				case <-time.After(5 * time.Second):
					t.Fatal("queued handler did not return after transaction release")
				}
				t.Error("canceled HTTP mutation remained behind the active transaction")
			}
			if status != http.StatusRequestTimeout {
				t.Errorf("canceled queued mutation dispatched: status=%d", status)
			}
			if tc.body != "" {
				for i := 0; i < 64; i++ {
					if _, err := s.Workflows.Preview(workflow.Request{Action: "discover"}); err != nil {
						t.Fatalf("canceled request consumed review-plan capacity after %d plans: %v", i, err)
					}
				}
			}
			select {
			case err := <-clientDone:
				if err == nil {
					t.Error("canceled client reported success")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled client did not stop")
			}
		})
	}
}

type blockedUpload struct {
	source   *bytes.Reader
	released chan struct{}
	once     sync.Once
}

func (b *blockedUpload) Read(p []byte) (int, error) { <-b.released; return b.source.Read(p) }
func (b *blockedUpload) Close() error               { b.once.Do(func() { close(b.released) }); return nil }

func TestSlowUploadDoesNotHoldMutationTransaction(t *testing.T) {
	s := makeServer(t)
	handler := s.Handler()
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/system/preview" {
			close(entered)
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	body := []byte(`{"action":"discover"}`)
	upload := &blockedUpload{source: bytes.NewReader(body), released: make(chan struct{})}
	defer upload.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/system/preview", upload)
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = int64(len(body))
	request.Header.Set("X-AccessWeaver-Token", s.Token)
	request.Header.Set("Content-Type", "application/json")
	first := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				err = io.ErrUnexpectedEOF
			}
		}
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("slow upload did not reach server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fast, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/system/cancel", nil)
	if err != nil {
		t.Fatal(err)
	}
	fast.Header.Set("X-AccessWeaver-Token", s.Token)
	response, err := client.Do(fast)
	if err != nil {
		t.Error("a slow upload blocked another mutation", err)
	} else {
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Errorf("independent mutation: %d", response.StatusCode)
		}
	}
	upload.Close()
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("released upload did not complete")
	}
}

type queueBody struct {
	io.ReadCloser
	reads     atomic.Int64
	bytesRead atomic.Int64
	consumed  chan<- struct{}
	once      sync.Once
}

func (b *queueBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	n, err := b.ReadCloser.Read(p)
	b.bytesRead.Add(int64(n))
	if err == io.EOF && b.consumed != nil {
		b.once.Do(func() { b.consumed <- struct{}{} })
	}
	return n, err
}

func TestMutationAdmissionBoundAndCanceledWaitersReleaseCapacity(t *testing.T) {
	s := makeServer(t)
	prepared := make(chan struct{}, maxPendingMutations)
	returned := make(chan int, maxPendingMutations)
	handler := s.Handler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.Body = &queueBody{ReadCloser: r.Body, consumed: prepared}
			response := &queueResponse{ResponseWriter: w}
			handler.ServeHTTP(response, r)
			returned <- response.status
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	admission, err := s.mutations.reserve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer admission()
	unlock, err := s.mutations.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	held := true
	release := func() {
		if held {
			unlock()
			held = false
		}
	}
	defer release()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	completed := make(chan error, maxPendingMutations)
	cancellations := []context.CancelFunc{}
	defer func() {
		for _, cancel := range cancellations {
			cancel()
		}
	}()
	for i := 0; i < maxPendingMutations-1; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancellations = append(cancellations, cancel)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/system/preview", strings.NewReader(`{"action":"discover"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-AccessWeaver-Token", s.Token)
		request.Header.Set("Content-Type", "application/json")
		go func() {
			response, err := client.Do(request)
			if response != nil {
				response.Body.Close()
			}
			completed <- err
		}()
		select {
		case <-prepared:
		case <-time.After(5 * time.Second):
			t.Fatal("admitted request was not prepared before waiting")
		}
	}
	overflow := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:54321/api/v1/system/preview", strings.NewReader(`{"action":"discover"}`))
	overflow.Header.Set("X-AccessWeaver-Token", s.Token)
	overflow.Header.Set("Content-Type", "application/json")
	body := &queueBody{ReadCloser: overflow.Body}
	overflow.Body = body
	ctx, cancel := context.WithCancel(overflow.Context())
	defer cancel()
	overflow = overflow.WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.Handler().ServeHTTP(response, overflow); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		release()
		<-done
		t.Fatal("overfull mutation was not rejected before waiting")
	}
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" || body.reads.Load() != 0 {
		t.Fatalf("overfull admission: status=%d retry=%q bodyReads=%d", response.Code, response.Header().Get("Retry-After"), body.reads.Load())
	}
	read := request(t, s, http.MethodGet, "/api/bootstrap", nil, s.Token, "127.0.0.1:54321")
	if read.Code != 200 {
		t.Fatal("full mutation admission blocked a metadata read")
	}
	unauthorized := request(t, s, http.MethodPost, "/api/v1/system/cancel", nil, "invalid", "127.0.0.1:54321")
	if unauthorized.Code != http.StatusForbidden {
		t.Fatal("full admission changed authentication")
	}
	for _, cancel := range cancellations {
		cancel()
	}
	for range cancellations {
		select {
		case status := <-returned:
			if status != http.StatusRequestTimeout {
				t.Errorf("canceled waiter dispatched: %d", status)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("canceled waiter retained admission or transaction wait")
		}
		select {
		case err := <-completed:
			if err == nil {
				t.Error("canceled queued client reported success")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("queued client did not stop")
		}
	}
	release()
	fresh := request(t, s, http.MethodPost, "/api/v1/system/preview", map[string]string{"action": "discover"}, s.Token, "127.0.0.1:54321")
	if fresh.Code != 200 {
		t.Fatalf("capacity did not recover: %d", fresh.Code)
	}
}

func TestMutationCancellationBeforeAdmissionDoesNotReadBody(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		s := makeServer(t)
		var ctx context.Context
		var cancel context.CancelFunc
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:54321/api/v1/system/preview", strings.NewReader(`{"action":"discover"}`)).WithContext(ctx)
		request.Header.Set("X-AccessWeaver-Token", s.Token)
		request.Header.Set("Content-Type", "application/json")
		body := &queueBody{ReadCloser: request.Body}
		request.Body = body
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, request)
		cancel()
		if response.Code != http.StatusRequestTimeout || body.reads.Load() != 0 {
			t.Fatalf("pre-ended request dispatched or read: status=%d reads=%d", response.Code, body.reads.Load())
		}
	}
}

func TestMutationBodyLimitAndRecovery(t *testing.T) {
	s := makeServer(t)
	for _, tc := range []struct {
		size    int
		unknown bool
		status  int
	}{
		{maxAPIRequestBodyBytes, false, http.StatusOK},
		{maxAPIRequestBodyBytes + 1, false, http.StatusRequestEntityTooLarge},
		{8 * maxAPIRequestBodyBytes, true, http.StatusRequestEntityTooLarge},
		{2, false, http.StatusOK},
	} {
		content := strings.Repeat(" ", tc.size-2) + "{}"
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:54321/api/v1/system/cancel", strings.NewReader(content))
		if tc.unknown {
			request.ContentLength = -1
		}
		request.Header.Set("X-AccessWeaver-Token", s.Token)
		request.Header.Set("Content-Type", "application/json")
		body := &queueBody{ReadCloser: request.Body}
		request.Body = body
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Fatalf("body boundary: bytes=%d unknown=%v status=%d", tc.size, tc.unknown, response.Code)
		}
		if tc.size > maxAPIRequestBodyBytes && !tc.unknown && body.reads.Load() != 0 {
			t.Fatal("declared oversized request was read before rejection")
		}
		if tc.unknown && body.bytesRead.Load() > maxAPIRequestBodyBytes+1 {
			t.Fatal("streamed request was read beyond the body guard")
		}

	}
}
