package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

func TestWorkflowHistoryResponsePreservesCompactResults(t *testing.T) {
	for _, result := range []string{`"` + strings.Repeat("<", 32768) + `"`, `"` + strings.Repeat("\u2028\u2029", 32768) + `"`} {
		s := makeServer(t)
		directory := filepath.Join(s.Store.Root, "workflows")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		original := []byte(`{"id":"response-fixture","action":"discover","state":"failed","result":` + result + `}`)
		file := filepath.Join(directory, "response-fixture.json")
		if err := os.WriteFile(file, original, 0600); err != nil {
			t.Fatal(err)
		}
		w := request(t, s, http.MethodGet, "/api/v1/system/history", nil, s.Token, "127.0.0.1")
		if w.Code != http.StatusOK {
			t.Fatalf("history response: %d", w.Code)
		}
		if w.Body.Len() > len(original)+1024 {
			t.Fatalf("history response expanded from %d to %d bytes", len(original), w.Body.Len())
		}
		if w.Header().Get("Content-Type") != "application/json; charset=utf-8" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("JSON MIME/privacy protections changed")
		}
		var rows []workflow.Job
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 1 {
			t.Fatalf("unreadable response: %v", err)
		}
		if !bytes.Equal(rows[0].Result, []byte(result)) {
			t.Fatal("complete result changed")
		}
		retained, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(retained, original) {
			t.Fatal("history export changed the original record")
		}
	}
}

type sizedWorkflowResponse struct {
	*httptest.ResponseRecorder
	largest int
}

func (w *sizedWorkflowResponse) Write(p []byte) (int, error) {
	w.largest = max(w.largest, len(p))
	return w.ResponseRecorder.Write(p)
}

func TestWorkflowHistoryResponseDoesNotWriteAnAggregateBuffer(t *testing.T) {
	s := makeServer(t)
	directory := filepath.Join(s.Store.Root, "workflows")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	result := `"` + strings.Repeat("x", 64<<10) + `"`
	for _, id := range []string{"a", "b", "c", "d"} {
		if err := os.WriteFile(filepath.Join(directory, id+".json"), []byte(`{"id":"`+id+`","state":"failed","result":`+result+`}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	w := &sizedWorkflowResponse{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system/history", nil)
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.largest > len(result)+1024 {
		t.Fatalf("aggregate history buffer: status=%d largestWrite=%d", w.Code, w.largest)
	}
	var rows []workflow.Job
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 4 {
		t.Fatalf("incomplete streamed array: %v", err)
	}
}

func TestSystemReportStreamingPreservesShapeAndRawResult(t *testing.T) {
	result := json.RawMessage(`"` + strings.Repeat("<", 64<<10) + `"`)
	w := &sizedWorkflowResponse{ResponseRecorder: httptest.NewRecorder()}
	streamWorkflowJSON(context.Background(), w, http.StatusOK, func(out io.Writer) error {
		return workflow.WriteSystemReportJSON(out, "fixture-os", workflow.Job{ID: "status-id", State: "failed", Result: result})
	})
	if w.Code != http.StatusOK || w.largest > len(result)+1024 || w.Body.Len() > len(result)+16384 {
		t.Fatalf("status result expanded: status=%d largest=%d size=%d", w.Code, w.largest, w.Body.Len())
	}
	var body struct {
		Platform   string
		Operations []workflow.Operation
		Job        workflow.Job
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Platform != "fixture-os" || len(body.Operations) != len(workflow.Catalog()) || !bytes.Equal(body.Job.Result, result) {
		t.Fatalf("status response changed: %v", err)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatal("report MIME guard changed")
	}
}

func TestWorkflowReportFailureBeforeOutputIsGenericAndNotSuccessful(t *testing.T) {
	w := httptest.NewRecorder()
	streamWorkflowJSON(context.Background(), w, http.StatusAccepted, func(out io.Writer) error {
		return workflow.WriteJobJSON(out, workflow.Job{Result: json.RawMessage(`PRIVATE_INVALID_ENCODING_FIXTURE`)})
	})
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "PRIVATE_INVALID_ENCODING_FIXTURE") || w.Body.String() != `{"error":"response encoding failed"}`+"\n" {
		t.Fatal("encoding failure committed success or disclosed its cause")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = httptest.NewRecorder()
	streamWorkflowJSON(ctx, w, http.StatusOK, func(out io.Writer) error { return workflow.WriteJobJSON(out, workflow.Job{ID: "private-job"}) })
	if w.Code != http.StatusRequestTimeout || strings.Contains(w.Body.String(), "private-job") {
		t.Fatal("ended export committed job data")
	}
}

func TestWorkflowReportsPreservePreviouslyAcceptedDeepJobs(t *testing.T) {
	s := makeServer(t)
	directory := filepath.Join(s.Store.Root, "workflows")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	result := strings.Repeat("[", 9999) + "0" + strings.Repeat("]", 9999)
	original := []byte(`{"id":"deep-fixture","state":"failed","result":` + result + `}`)
	if err := os.WriteFile(filepath.Join(directory, "deep.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, http.MethodGet, "/api/v1/system/history", nil, s.Token, "127.0.0.1")
	if w.Code != http.StatusOK {
		t.Fatalf("previously accepted job rejected: %d", w.Code)
	}
	// Each retained Job fits Go's decoder limit. The existing JSON report wraps
	// that value one level deeper; consumers retain their own document limits.
	array := bytes.TrimSpace(w.Body.Bytes())
	if len(array) < 2 || array[0] != '[' || array[len(array)-1] != ']' {
		t.Fatal("response array shape changed")
	}
	var job workflow.Job
	if err := json.Unmarshal(array[1:len(array)-1], &job); err != nil || !bytes.Equal(job.Result, []byte(result)) {
		t.Fatalf("deep job not retained: %v", err)
	}
}

func TestSystemStatusAdmissionKeepsHistoryAndCancellationAvailable(t *testing.T) {
	s := makeServer(t)
	response := &heldHistoryResponse{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(response.release) }) }
	defer func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("held status response did not stop")
		}
	}()
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system", nil)
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	go func() { defer close(done); s.Handler().ServeHTTP(response, r) }()
	select {
	case <-response.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("status response did not start")
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := request(t, s, method, "/api/v1/system", nil, s.Token, "127.0.0.1")
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
			t.Fatal("overlapping status read not bounded")
		}
	}
	for _, route := range []struct{ method, path string }{{http.MethodGet, "/api/bootstrap"}, {http.MethodGet, "/api/v1/system/history"}, {http.MethodPost, "/api/v1/system/cancel"}} {
		if w := request(t, s, route.method, route.path, nil, s.Token, "127.0.0.1"); w.Code != http.StatusOK {
			t.Fatalf("control blocked by status export: %s %d", route.path, w.Code)
		}
	}
	if w := request(t, s, http.MethodGet, "/api/v1/system", nil, "wrong", "127.0.0.1"); w.Code != http.StatusForbidden {
		t.Fatal("busy response bypassed authentication")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ended := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system", nil).WithContext(ctx)
	ended.Header.Set("X-AccessWeaver-Token", s.Token)
	endedResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(endedResponse, ended)
	if endedResponse.Code != http.StatusRequestTimeout {
		t.Fatal("ended status read was admitted")
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("status response did not finish")
	}
	if w := request(t, s, http.MethodGet, "/api/v1/system", nil, s.Token, "127.0.0.1"); w.Code != http.StatusOK {
		t.Fatal("completed status response retained its slot")
	}
}

func TestSystemStatusAbortedResponseReleasesAdmission(t *testing.T) {
	s := makeServer(t)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/system", nil)
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	func() {
		defer func() {
			if recovered := recover(); recovered != http.ErrAbortHandler {
				t.Fatalf("response not aborted: %v", recovered)
			}
		}()
		s.Handler().ServeHTTP(failedHistoryResponse{httptest.NewRecorder()}, r)
	}()
	if w := request(t, s, http.MethodGet, "/api/v1/system", nil, s.Token, "127.0.0.1"); w.Code != http.StatusOK {
		t.Fatal("aborted status kept its admission slot")
	}
}

func TestBrokenWorkflowStreamIsAnIncompleteHTTPResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		streamWorkflowJSON(r.Context(), w, http.StatusOK, func(out io.Writer) error {
			if _, err := out.Write([]byte(`{"private":"partial`)); err != nil {
				return err
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return err
			}
			return errors.New("synthetic failure after bytes were sent")
		})
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if !errors.Is(err, io.ErrUnexpectedEOF) || json.Valid(body) {
		t.Fatalf("aborted raw download did not end as an incomplete HTTP message: %v", err)
	}
}
