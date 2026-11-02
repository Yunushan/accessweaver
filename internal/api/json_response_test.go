package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLargeJSONResponsesPreserveRepresentationAndFraming(t *testing.T) {
	value := map[string]string{"value": strings.Repeat("framing-fixture<&>", 4096)}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	want := append(encoded, '\n')
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		JSON(w, http.StatusAccepted, value)
	}))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, method := range []string{http.MethodGet, http.MethodGet, http.MethodHead} {
		request, err := http.NewRequest(method, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Close = true
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(want)+1)))
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusAccepted || (response.ContentLength >= 0 && response.ContentLength != int64(len(want))) {
			t.Fatalf("unexpected response framing: method=%s status=%d contentLength=%d transferEncoding=%v", method, response.StatusCode, response.ContentLength, response.TransferEncoding)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatal("JSON response headers changed")
		}
		if method == http.MethodHead {
			if len(body) != 0 {
				t.Fatal("HEAD returned a response body")
			}
		} else if string(body) != string(want) {
			t.Fatal("JSON response encoding changed")
		}
	}
}

type failedJSONValue struct{}

func (failedJSONValue) MarshalJSON() ([]byte, error) {
	return nil, errors.New("private-serialization-error-must-not-leak")
}

func TestJSONEncodingFailureReturnsValidErrorBeforeHeaders(t *testing.T) {
	for _, value := range []any{failedJSONValue{}, json.RawMessage(`{"private":"unfinished`)} {
		response := httptest.NewRecorder()
		JSON(response, http.StatusAccepted, value)
		result := response.Result()
		defer result.Body.Close()
		body, err := io.ReadAll(result.Body)
		if err != nil {
			t.Fatal(err)
		}
		if result.StatusCode != http.StatusInternalServerError {
			t.Fatalf("encoding failure reported success: %d", result.StatusCode)
		}
		var problem map[string]string
		if err := json.Unmarshal(body, &problem); err != nil || problem["error"] == "" {
			t.Fatalf("missing JSON error response: %v", err)
		}
		if strings.Contains(string(body), "private") || strings.Contains(string(body), "unfinished") {
			t.Fatal("serialization failure disclosed private data")
		}
		if result.Header.Get("Cache-Control") != "no-store" || result.Header.Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatal("error response has incorrect content type or caching")
		}
	}
}
