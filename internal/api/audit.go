package api

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// NewProfileAudited constructs a deliberately limited profile-editing desktop.
// The caller owns recorder lifetime and must hold the controller data lock.
// The recorder cannot be enabled/disabled by HTTP input. Ordinary New remains
// separate; this is not machine-wide mandatory audit enforcement.
func NewProfileAudited(store *profile.Store, manager *engine.Manager, static fs.FS, recorder *audit.Recorder) (*Server, error) {
	if recorder == nil {
		return nil, audit.ErrRecorderUnavailable
	}
	s, err := New(store, manager, static)
	if err != nil {
		return nil, err
	}
	s.profileAudit = recorder
	return s, nil
}
func (s *Server) profileChange(ctx context.Context, action string, operation func(context.Context) error) error {
	if s.profileAudit == nil {
		return operation(ctx)
	}
	return s.profileAudit.Execute(ctx, action, func(ctx context.Context) audit.OperationResult {
		err := operation(ctx)
		if err == nil {
			return audit.OperationResult{Outcome: "completed"}
		}
		// Effects or final cleanup may already have occurred. Retained refusal
		// causes cannot prove that this mutation was absent.
		if errors.Is(err, profile.ErrMutationUncertain) {
			return audit.OperationResult{Outcome: "indeterminate", Err: err}
		}
		// A read/cleanup cofailure stays uncertain even when its retained causes
		// also include a normally refused revision, contention or policy result.
		if errors.Is(err, profile.ErrReadUnavailable) || errors.Is(err, filelock.ErrCloseUncertain) {
			return audit.OperationResult{Outcome: "indeterminate", Err: err}
		}
		// These store contracts refuse before saving/deleting. Cancellation or
		// unknown I/O may race with commit, so neither is asserted absent.
		if errors.Is(err, profile.ErrConflict) || errors.Is(err, profile.ErrStoreBusy) || managed.IsPolicyError(err) {
			return audit.OperationResult{Outcome: "refused", Err: err}
		}
		return audit.OperationResult{Outcome: "indeterminate", Err: err}
	})
}
func (s *Server) profileAuditAllows(r *http.Request) bool {
	if s.profileAudit == nil || !strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	path := r.URL.Path
	profile := strings.HasPrefix(path, "/api/v1/profiles/") && len(strings.TrimPrefix(path, "/api/v1/profiles/")) > 0 && !strings.Contains(strings.TrimPrefix(path, "/api/v1/profiles/"), "/")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return path == "/api/bootstrap" || path == "/api/v1/engines" || path == "/api/v1/profiles" || profile || path == "/api/v1/runtime"
	case http.MethodPut, http.MethodDelete:
		return profile
	case http.MethodPost:
		return path == "/api/v1/preview"
	}
	return false
}
