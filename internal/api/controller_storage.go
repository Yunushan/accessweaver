package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func failControllerStorage(w http.ResponseWriter, err error, read bool) {
	status, code, message := http.StatusServiceUnavailable, "workflow-storage-unavailable", "controller storage accounting is unavailable; preserve existing evidence"
	switch {
	case errors.Is(err, managed.ErrDenied):
		status, code, message = http.StatusForbidden, "workflow-storage-denied", "controller storage inspection is not permitted by the current policy"
	case errors.Is(err, managed.ErrUnavailable):
		code, message = "workflow-storage-policy-unavailable", "controller storage policy is unavailable"
	case errors.Is(err, workflow.ErrWorkflowBusy):
		code, message = "workflow-storage-busy", "controller storage inspection is busy; try again shortly"
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, workflow.ErrWorkflowStore):
		message = "controller storage coordination is unavailable; preserve existing evidence"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status, code, message = http.StatusRequestTimeout, "workflow-storage-request-ended", "controller storage request ended before completion"
	case errors.Is(err, workflow.ErrWorkflowStorageCapacity):
		status, code, message = http.StatusConflict, "workflow-storage-capacity", workflow.ErrWorkflowStorageCapacity.Error()
	case errors.Is(err, workflow.ErrWorkflowStoragePending):
		code, message = "workflow-storage-pending", workflow.ErrWorkflowStoragePending.Error()
		if !read {
			status = http.StatusConflict
		}
	}
	JSON(w, status, map[string]string{"error": message, "code": code})
}

// Accounting has an independent bounded read slot. It cannot queue behind a
// history transfer or hold the current-job Cancel/profile mutation admission.
func (s *Server) controllerStorageStatus(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		JSON(w, http.StatusBadRequest, map[string]string{"error": "invalid controller storage status request", "code": "workflow-storage-invalid"})
		return
	}
	if err := r.Context().Err(); err != nil {
		failControllerStorage(w, err, true)
		return
	}
	if !s.controllerStorageRead.TryLock() {
		failControllerStorage(w, workflow.ErrWorkflowBusy, true)
		return
	}
	defer s.controllerStorageRead.Unlock()
	if s.Workflows == nil {
		failControllerStorage(w, errors.New("controller storage backend unavailable"), true)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	value, err := s.Workflows.ControllerStorageStatus(ctx)
	if err != nil {
		failControllerStorage(w, err, true)
		return
	}
	writeControllerStorageMetadata(w, value)
}
func writeControllerStorageMetadata(w http.ResponseWriter, value workflow.ControllerStorageStatus) {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > 4096 {
		failControllerStorage(w, errors.New("controller storage status encoding unavailable"), true)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(data, '\n'))
}
