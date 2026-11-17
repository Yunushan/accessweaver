package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

const workflowLifecyclePendingCode = "workflow-lifecycle-pending"

func failWorkflowStart(w http.ResponseWriter, err error) {
	if errors.Is(err, workflow.ErrWorkflowStorageCapacity) || errors.Is(err, workflow.ErrWorkflowStoragePending) {
		failControllerStorage(w, err, false)
		return
	}
	if errors.Is(err, workflow.ErrWorkflowLifecyclePending) {
		JSON(w, http.StatusConflict, map[string]string{"error": workflow.ErrWorkflowLifecyclePending.Error(), "code": workflowLifecyclePendingCode})
		return
	}
	failProfile(w, err, http.StatusConflict)
}

// This metadata read owns a separate slot from history transfers, mutations,
// current-job status and cancellation. It never initializes a missing store.
func (s *Server) workflowLifecycle(w http.ResponseWriter, r *http.Request) {
	if _, err := historyBrowserQuery(r); err != nil {
		fail(w, http.StatusBadRequest, "invalid workflow completion status request")
		return
	}
	if !s.lifecycleRead.TryLock() {
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusServiceUnavailable, "workflow completion status is busy; try again shortly")
		return
	}
	defer s.lifecycleRead.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, err := s.Workflows.LifecycleStatus(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			fail(w, http.StatusRequestTimeout, "workflow completion status request ended before completion")
		} else if errors.Is(err, workflow.ErrWorkflowLifecyclePending) {
			JSON(w, http.StatusConflict, map[string]string{"error": workflow.ErrWorkflowLifecyclePending.Error(), "code": workflowLifecyclePendingCode})
		} else {
			fail(w, http.StatusServiceUnavailable, "workflow completion status is unavailable")
		}
		return
	}
	JSON(w, http.StatusOK, status)
}
