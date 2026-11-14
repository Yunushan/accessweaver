package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestEnginePreparationPreviewObservesRequestCancellation(t *testing.T) {
	guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	store, err := profile.NewStoreWithGuard(t.TempDir(), guard)
	if err != nil {
		t.Fatal("owned store unavailable")
	}
	server, err := New(store, engine.NewManagerWithGuard(store.Root, guard), nil)
	if err != nil {
		t.Fatal("owned server unavailable")
	}
	server.Policy = guard
	for _, phase := range []string{"canceled", "expired"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if phase == "expired" {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				cancel()
			}
			defer cancel()
			p := profile.New("canceled-preview", "PRIVATE_PROFILE_VALUE", "byedpi")
			p.Binary = "PRIVATE_BINARY_PATH"
			body, err := json.Marshal(p)
			if err != nil {
				t.Fatal("source profile encode failed")
			}
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:54321/api/v1/preview", bytes.NewReader(body)).WithContext(ctx)
			request.Host = "127.0.0.1:54321"
			request.Header.Set("X-AccessWeaver-Token", server.Token)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusRequestTimeout || strings.Contains(response.Body.String(), "PRIVATE_") || response.Header().Get("Retry-After") != "" {
				t.Fatal("canceled preview ignored request context or exposed private details")
			}
			if state := server.Manager.Snapshot(); state.State != "stopped" || state.PID != 0 {
				t.Fatal("canceled preview changed runtime")
			}
		})
	}
}

func TestEnginePreparationErrorPrecedence(t *testing.T) {
	for _, row := range []struct {
		name   string
		err    error
		status int
		fixed  string
	}{
		{"canceled", context.Canceled, http.StatusRequestTimeout, "context canceled"},
		{"expired", context.DeadlineExceeded, http.StatusRequestTimeout, "context deadline exceeded"},
		{"cleanup-uncertain", errors.Join(context.Canceled, engine.ErrPreparationCleanupUncertain, errors.New("PRIVATE_CLEANUP_DETAIL")), http.StatusServiceUnavailable, engine.ErrPreparationCleanupUncertain.Error()},
		{"atomic-uncertainty", errors.Join(context.Canceled, profile.ErrAtomicWriteUncertain), http.StatusServiceUnavailable, profile.ErrAtomicWriteUncertain.Error()},
		{"denied", errors.Join(context.Canceled, managed.ErrDenied), http.StatusForbidden, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			failEnginePreparation(response, row.err)
			var body struct {
				Error string `json:"error"`
				Code  string `json:"code"`
			}
			if json.Unmarshal(response.Body.Bytes(), &body) != nil {
				t.Fatal("invalid error response")
			}
			if response.Code != row.status || (row.fixed != "" && body.Error != row.fixed) || response.Header().Get("Retry-After") != "" {
				t.Fatal("cancellation overrode uncertainty or policy classification")
			}
			if (body.Code == "engine-preparation-restart-required") != (row.name == "cleanup-uncertain") {
				t.Fatal("cleanup restart code did not match the error category")
			}
		})
	}
}
