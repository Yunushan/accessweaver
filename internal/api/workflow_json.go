package api

import (
	"context"
	"io"
	"net/http"
	"runtime"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

type workflowJSONResponse struct {
	context  context.Context
	response http.ResponseWriter
	status   int
	started  bool
}

func (w *workflowJSONResponse) Write(data []byte) (int, error) {
	if err := w.context.Err(); err != nil {
		return 0, err
	}
	if !w.started {
		w.started = true
		w.response.WriteHeader(w.status)
	}
	return w.response.Write(data)
}

// Report encoders preflight their values before the first Write. Keep an
// encoding failure a generic non-success JSON response. A failure after output
// starts must abort HTTP framing so a raw-download client cannot save a partial
// document as a completed successful response.
func streamWorkflowJSON(ctx context.Context, w http.ResponseWriter, status int, encode func(io.Writer) error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	out := &workflowJSONResponse{context: ctx, response: w, status: status}
	if err := encode(out); err != nil {
		if out.started {
			panic(http.ErrAbortHandler)
		}
		if ctx.Err() != nil {
			fail(w, http.StatusRequestTimeout, "workflow report request ended before export completed")
			return
		}
		fail(w, http.StatusInternalServerError, "response encoding failed")
	}
}

func (s *Server) workflowStatus(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() != nil {
		fail(w, http.StatusRequestTimeout, "workflow report request ended before export completed")
		return
	}
	// Acquire before Snapshot clones the result. Slow readers share one status
	// slot while history exports, foreground status and cancellation stay separate.
	if !s.statusRead.TryLock() {
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusServiceUnavailable, "another system report is in progress; try again shortly")
		return
	}
	defer s.statusRead.Unlock()
	job := s.Workflows.Snapshot()
	streamWorkflowJSON(r.Context(), w, http.StatusOK, func(out io.Writer) error { return workflow.WriteSystemReportJSON(out, runtime.GOOS, job) })
}

func workflowJobJSON(w http.ResponseWriter, r *http.Request, status int, job workflow.Job) {
	streamWorkflowJSON(r.Context(), w, status, func(out io.Writer) error { return workflow.WriteJobJSON(out, job) })
}
