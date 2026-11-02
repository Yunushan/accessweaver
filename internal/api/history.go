package api

import (
	"io"
	"net/http"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

func (s *Server) workflowHistory(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() != nil {
		fail(w, http.StatusRequestTimeout, "history request ended before export completed")
		return
	}
	// Hold admission through encoding and writing, not just the disk scan. Slow
	// readers must not retain independent large copies of the entire history.
	// Every Handler for this Server shares this gate; controls use other gates.
	if !s.historyRead.TryLock() {
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusServiceUnavailable, "another workflow history export is in progress; try again shortly")
		return
	}
	defer s.historyRead.Unlock()
	items, err := s.Workflows.HistoryContext(r.Context())
	if r.Context().Err() != nil {
		fail(w, http.StatusRequestTimeout, "history request ended before export completed")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	streamWorkflowJSON(r.Context(), w, http.StatusOK, func(out io.Writer) error { return workflow.WriteHistoryReportJSON(out, items) })
}
