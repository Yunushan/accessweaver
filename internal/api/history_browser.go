package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

const historyBrowserMaximumQueryBytes = 4096

// Every selected-record read shares the existing heavy history slot through
// response completion. A slow download cannot multiply retained large records.
func (s *Server) admitHistoryBrowser(w http.ResponseWriter, r *http.Request) bool {
	if r.Context().Err() != nil {
		failHistoryBrowser(w, r.Context().Err())
		return false
	}
	if !s.historyRead.TryLock() {
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusServiceUnavailable, "another workflow history export is in progress; try again shortly")
		return false
	}
	return true
}

func failHistoryBrowser(w http.ResponseWriter, err error) {
	status, message := http.StatusInternalServerError, "workflow history is unavailable"
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status, message = http.StatusRequestTimeout, "workflow history request ended before completion"
	case errors.Is(err, workflow.ErrHistoryInvalidRequest):
		status, message = http.StatusBadRequest, workflow.ErrHistoryInvalidRequest.Error()
	case errors.Is(err, workflow.ErrHistoryInventoryNeeded):
		status, message = http.StatusConflict, workflow.ErrHistoryInventoryNeeded.Error()
	case errors.Is(err, workflow.ErrHistoryInventoryStale):
		status, message = http.StatusConflict, workflow.ErrHistoryInventoryStale.Error()
	case errors.Is(err, workflow.ErrHistoryRecordUnavailable):
		status, message = http.StatusNotFound, workflow.ErrHistoryRecordUnavailable.Error()
	case errors.Is(err, workflow.ErrHistoryStagingPending):
		JSON(w, http.StatusConflict, map[string]string{"error": workflow.ErrHistoryStagingPending.Error(), "code": "history-staging-pending"})
		return
	case errors.Is(err, workflow.ErrHistoryCapacity):
		status, message = http.StatusRequestEntityTooLarge, workflow.ErrHistoryCapacity.Error()
	case errors.Is(err, workflow.ErrWorkflowBusy):
		status, message = http.StatusServiceUnavailable, workflow.ErrWorkflowBusy.Error()
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, workflow.ErrHistoryUnavailable), errors.Is(err, workflow.ErrWorkflowStore):
		message = workflow.ErrHistoryUnavailable.Error()
	}
	fail(w, status, message)
}

func historyBrowserQuery(r *http.Request, allowed ...string) (url.Values, error) {
	if len(r.URL.RawQuery) > historyBrowserMaximumQueryBytes {
		return nil, workflow.ErrHistoryInvalidRequest
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, workflow.ErrHistoryInvalidRequest
	}
	for key, value := range values {
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known || len(value) != 1 {
			return nil, workflow.ErrHistoryInvalidRequest
		}
	}
	return values, nil
}

func historyBrowserHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			if digit < 'a' || digit > 'f' {
				return false
			}
		}
	}
	return true
}

func historyBrowserOpaque(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func (s *Server) workflowHistoryInventory(w http.ResponseWriter, r *http.Request) {
	if !s.admitHistoryBrowser(w, r) {
		return
	}
	defer s.historyRead.Unlock()
	if _, err := historyBrowserQuery(r); err != nil {
		failHistoryBrowser(w, err)
		return
	}
	var request map[string]json.RawMessage
	if err := readJSON(w, r, &request); err != nil || request == nil || len(request) != 0 {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			fail(w, http.StatusRequestEntityTooLarge, "workflow history request is too large")
		} else if r.Context().Err() != nil {
			failHistoryBrowser(w, r.Context().Err())
		} else {
			failHistoryBrowser(w, workflow.ErrHistoryInvalidRequest)
		}
		return
	}
	inventory, err := s.Workflows.CaptureHistoryInventory(r.Context())
	if err != nil {
		failHistoryBrowser(w, err)
		return
	}
	writeHistoryBrowserMetadata(w, r, inventory)
}

func (s *Server) workflowHistoryPage(w http.ResponseWriter, r *http.Request) {
	if !s.admitHistoryBrowser(w, r) {
		return
	}
	defer s.historyRead.Unlock()
	values, err := historyBrowserQuery(r, "limit", "cursor", "snapshot")
	if err != nil {
		failHistoryBrowser(w, err)
		return
	}
	for _, name := range []string{"limit", "cursor", "snapshot"} {
		if values.Has(name) && values.Get(name) == "" {
			failHistoryBrowser(w, workflow.ErrHistoryInvalidRequest)
			return
		}
	}
	query := workflow.HistoryPageQuery{Cursor: values.Get("cursor"), Snapshot: values.Get("snapshot")}
	if text := values.Get("limit"); text != "" {
		for _, digit := range text {
			if digit < '0' || digit > '9' {
				failHistoryBrowser(w, workflow.ErrHistoryInvalidRequest)
				return
			}
		}
		query.Limit, err = strconv.Atoi(text)
		if err != nil || query.Limit < 1 || query.Limit > 128 {
			failHistoryBrowser(w, workflow.ErrHistoryInvalidRequest)
			return
		}
	}
	if query.Cursor != "" && !historyBrowserOpaque(query.Cursor) || query.Snapshot != "" && !historyBrowserHex(query.Snapshot, 48) {
		failHistoryBrowser(w, workflow.ErrHistoryInvalidRequest)
		return
	}
	page, err := s.Workflows.HistoryPage(r.Context(), query)
	if err != nil {
		failHistoryBrowser(w, err)
		return
	}
	writeHistoryBrowserMetadata(w, r, page)
}

func historyBrowserSelection(r *http.Request, allowEmptyRevision bool) (string, string, error) {
	values, err := historyBrowserQuery(r, "revision")
	ref, revision := r.PathValue("recordRef"), values.Get("revision")
	if err != nil || !values.Has("revision") || !historyBrowserOpaque(ref) || revision != "" && !historyBrowserHex(revision, 64) || revision == "" && !allowEmptyRevision {
		return "", "", workflow.ErrHistoryInvalidRequest
	}
	return ref, revision, nil
}

func (s *Server) workflowHistoryRecord(w http.ResponseWriter, r *http.Request) {
	if !s.admitHistoryBrowser(w, r) {
		return
	}
	defer s.historyRead.Unlock()
	ref, revision, err := historyBrowserSelection(r, true)
	if err != nil {
		failHistoryBrowser(w, err)
		return
	}
	detail, err := s.Workflows.ReadHistoryRecord(r.Context(), ref, revision)
	if err != nil {
		failHistoryBrowser(w, err)
		return
	}
	if r.Context().Err() != nil {
		failHistoryBrowser(w, r.Context().Err())
		return
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		return
	}
	streamWorkflowJSON(r.Context(), w, http.StatusOK, func(out io.Writer) error {
		return workflow.WriteHistoryRecordDetailJSON(historyBrowserWriter{r.Context(), out}, detail)
	})
}

func (s *Server) workflowHistoryRecordExport(w http.ResponseWriter, r *http.Request) {
	if !s.admitHistoryBrowser(w, r) {
		return
	}
	defer s.historyRead.Unlock()
	ref, revision, err := historyBrowserSelection(r, false)
	if err != nil {
		failHistoryBrowser(w, err)
		return
	}
	data, err := s.Workflows.ReadHistoryRecordRaw(r.Context(), ref, revision)
	if err != nil {
		failHistoryBrowser(w, err)
		return
	}
	if r.Context().Err() != nil {
		failHistoryBrowser(w, r.Context().Err())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="accessweaver-workflow-record.bin"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", `"`+revision+`"`)
	w.Header().Set("X-AccessWeaver-Revision", revision)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	out := &workflowJSONResponse{context: r.Context(), response: w, status: http.StatusOK}
	if _, err := (historyBrowserWriter{r.Context(), out}).Write(data); err != nil {
		if out.started {
			panic(http.ErrAbortHandler)
		}
		for _, name := range []string{"Content-Disposition", "Content-Length", "ETag", "X-AccessWeaver-Revision"} {
			w.Header().Del(name)
		}
		failHistoryBrowser(w, err)
		return
	}
	if !out.started {
		w.WriteHeader(http.StatusOK)
	}
}

// This wrapper bounds individual writes and adds cancellation checkpoints even
// when a complete retained raw result is handed to it as one byte slice.
type historyBrowserWriter struct {
	ctx context.Context
	out io.Writer
}

func (w historyBrowserWriter) Write(data []byte) (int, error) {
	written := 0
	for len(data) != 0 {
		if err := w.ctx.Err(); err != nil {
			return written, err
		}
		chunk := data[:min(len(data), 32<<10)]
		n, err := w.out.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		if n != len(chunk) {
			return written, io.ErrShortWrite
		}
		data = data[n:]
	}
	return written, w.ctx.Err()
}

func writeHistoryBrowserMetadata(w http.ResponseWriter, r *http.Request, value any) {
	// Inventory/page metadata is bounded by the catalog's fixed field limits
	// and at most128 rows; selected Job/Result bytes never enter this encoder.
	streamWorkflowJSON(r.Context(), w, http.StatusOK, func(out io.Writer) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		encoded = append(encoded, '\n')
		if err := r.Context().Err(); err != nil {
			return err
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return nil
		}
		_, err = (historyBrowserWriter{r.Context(), out}).Write(encoded)
		return err
	})
}
