package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

const reconciliationRequestBytes = 4096

// These two explicit metadata operations own their own nonqueued gate and
// backend root leases. A pending file operation must not block workflow Cancel,
// current status, ordinary profile editing or independent network diagnostics.
func reconciliationMutationPath(r *http.Request) bool {
	return r.Method == http.MethodPost && (r.URL.Path == "/api/v1/system/history/reconciliation/preview" || r.URL.Path == "/api/v1/system/history/reconciliation/apply")
}

func failReconciliation(w http.ResponseWriter, err error, read bool) {
	status, code, message := http.StatusInternalServerError, "reconciliation-unavailable", "workflow reconciliation is unavailable; preserve its evidence"
	switch {
	case errors.Is(err, workflow.ErrLifecycleReconciliationInvalidRequest):
		status, code, message = http.StatusBadRequest, "reconciliation-invalid", workflow.ErrLifecycleReconciliationInvalidRequest.Error()
	case errors.Is(err, managed.ErrDenied):
		status, code, message = http.StatusForbidden, "reconciliation-denied", "workflow reconciliation is not permitted by the current policy"
	case errors.Is(err, managed.ErrUnavailable):
		status, code, message = http.StatusServiceUnavailable, "reconciliation-policy-unavailable", "workflow reconciliation policy is unavailable"
	case errors.Is(err, workflow.ErrWorkflowBusy):
		status, code, message = http.StatusServiceUnavailable, "reconciliation-busy", "workflow reconciliation is busy; try again shortly"
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, workflow.ErrWorkflowStore):
		status, code, message = http.StatusServiceUnavailable, "reconciliation-store-unavailable", workflow.ErrWorkflowStore.Error()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status, code, message = http.StatusRequestTimeout, "reconciliation-request-ended", "workflow reconciliation request ended before completion; inspect its known operation"
	case errors.Is(err, workflow.ErrLifecycleReconciliationConflict):
		status, code, message = http.StatusConflict, "reconciliation-conflict", workflow.ErrLifecycleReconciliationConflict.Error()
	case errors.Is(err, workflow.ErrLifecycleReconciliationExpired):
		status, code, message = http.StatusConflict, "reconciliation-expired", workflow.ErrLifecycleReconciliationExpired.Error()
	case errors.Is(err, workflow.ErrLifecycleReconciliationPending):
		status, code, message = http.StatusConflict, "reconciliation-pending", workflow.ErrLifecycleReconciliationPending.Error()
	case errors.Is(err, workflow.ErrLifecycleReconciliationUnavailable):
		status, code, message = http.StatusConflict, "reconciliation-unavailable", workflow.ErrLifecycleReconciliationUnavailable.Error()
		if read {
			status = http.StatusServiceUnavailable
		}
	}
	JSON(w, status, map[string]string{"error": message, "code": code})
}

func reconciliationQuery(r *http.Request) error {
	if r.URL.RawQuery != "" {
		return workflow.ErrLifecycleReconciliationInvalidRequest
	}
	return r.Context().Err()
}

// Decode a closed object rather than allowing case aliases, duplicate decoded
// keys, null primitives or a second JSON document to change the reviewed scope.
// Read to the bounded EOF before root I/O so disconnect cancellation is active.
func readReconciliationObject(w http.ResponseWriter, r *http.Request, allowed ...string) (map[string]json.RawMessage, error) {
	if err := reconciliationQuery(r); err != nil {
		return nil, err
	}
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(parameters) > 1 || (parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8")) {
		return nil, workflow.ErrLifecycleReconciliationInvalidRequest
	}
	for name := range parameters {
		if name != "charset" {
			return nil, workflow.ErrLifecycleReconciliationInvalidRequest
		}
	}
	if r.Body == nil {
		return nil, workflow.ErrLifecycleReconciliationInvalidRequest
	}
	r.Body = http.MaxBytesReader(w, r.Body, reconciliationRequestBytes)
	data, err := io.ReadAll(r.Body)
	if contextErr := r.Context().Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil || !utf8.Valid(data) {
		return nil, workflow.ErrLifecycleReconciliationInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, workflow.ErrLifecycleReconciliationInvalidRequest
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, workflow.ErrLifecycleReconciliationInvalidRequest
		}
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known {
			return nil, workflow.ErrLifecycleReconciliationInvalidRequest
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, workflow.ErrLifecycleReconciliationInvalidRequest
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, workflow.ErrLifecycleReconciliationInvalidRequest
		}
		fields[key] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return nil, workflow.ErrLifecycleReconciliationInvalidRequest
	}
	return fields, nil
}

func reconciliationString(fields map[string]json.RawMessage, key string, required bool) (string, error) {
	raw, exists := fields[key]
	if !exists && !required {
		return "", nil
	}
	var value string
	if !exists || len(raw) < 2 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil || !historyBrowserHex(value, 48) {
		return "", workflow.ErrLifecycleReconciliationInvalidRequest
	}
	return value, nil
}

func writeReconciliationMetadata(w http.ResponseWriter, value any, limit int) {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > limit {
		failReconciliation(w, errors.New("reconciliation metadata encoding unavailable"), true)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(data, '\n'))
}

func (s *Server) admitReconciliationRead(w http.ResponseWriter, r *http.Request) bool {
	if err := reconciliationQuery(r); err != nil {
		failReconciliation(w, err, true)
		return false
	}
	if !s.reconciliationRead.TryLock() {
		failReconciliation(w, workflow.ErrWorkflowBusy, true)
		return false
	}
	if s.Workflows == nil {
		s.reconciliationRead.Unlock()
		failReconciliation(w, workflow.ErrLifecycleReconciliationUnavailable, true)
		return false
	}
	return true
}

func (s *Server) workflowReconciliationStatus(w http.ResponseWriter, r *http.Request) {
	if !s.admitReconciliationRead(w, r) {
		return
	}
	defer s.reconciliationRead.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, err := s.Workflows.LifecycleReconciliationStatus(ctx)
	if err != nil {
		failReconciliation(w, err, true)
		return
	}
	writeReconciliationMetadata(w, status, 4096)
}

func (s *Server) workflowReconciliationReceipt(w http.ResponseWriter, r *http.Request) {
	operation := r.PathValue("operationId")
	if !historyBrowserHex(operation, 48) {
		failReconciliation(w, workflow.ErrLifecycleReconciliationInvalidRequest, true)
		return
	}
	if !s.admitReconciliationRead(w, r) {
		return
	}
	defer s.reconciliationRead.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	receipt, err := s.Workflows.ReadLifecycleReconciliationReceipt(ctx, operation)
	if err != nil {
		failReconciliation(w, err, true)
		return
	}
	writeReconciliationMetadata(w, receipt, 64<<10)
}

func (s *Server) admitReconciliationMutation(w http.ResponseWriter, r *http.Request) bool {
	if err := reconciliationQuery(r); err != nil {
		failReconciliation(w, err, false)
		return false
	}
	if !s.reconciliationWrite.TryLock() {
		failReconciliation(w, workflow.ErrWorkflowBusy, false)
		return false
	}
	if s.Workflows == nil {
		s.reconciliationWrite.Unlock()
		failReconciliation(w, workflow.ErrLifecycleReconciliationUnavailable, false)
		return false
	}
	return true
}

func (s *Server) workflowReconciliationPreview(w http.ResponseWriter, r *http.Request) {
	if !s.admitReconciliationMutation(w, r) {
		return
	}
	defer s.reconciliationWrite.Unlock()
	fields, err := readReconciliationObject(w, r, "generation", "operationId")
	if err != nil {
		failReconciliation(w, err, false)
		return
	}
	generation, err := reconciliationString(fields, "generation", false)
	if err != nil {
		failReconciliation(w, err, false)
		return
	}
	operation, err := reconciliationString(fields, "operationId", false)
	if err != nil || generation != "" && operation != "" {
		failReconciliation(w, workflow.ErrLifecycleReconciliationInvalidRequest, false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	plan, err := s.Workflows.PreviewLifecycleReconciliation(ctx, workflow.LifecycleReconciliationRequest{Generation: generation, OperationID: operation})
	if err != nil {
		failReconciliation(w, err, false)
		return
	}
	writeReconciliationMetadata(w, plan, 64<<10)
}

func (s *Server) workflowReconciliationApply(w http.ResponseWriter, r *http.Request) {
	if !s.admitReconciliationMutation(w, r) {
		return
	}
	defer s.reconciliationWrite.Unlock()
	fields, err := readReconciliationObject(w, r, "planId", "confirm")
	if err != nil {
		failReconciliation(w, err, false)
		return
	}
	plan, err := reconciliationString(fields, "planId", true)
	if err != nil || !bytes.Equal(bytes.TrimSpace(fields["confirm"]), []byte("true")) {
		failReconciliation(w, workflow.ErrLifecycleReconciliationInvalidRequest, false)
		return
	}
	// After its first publication begins, Manager retains and drains the actual
	// operation even if this waiting HTTP client or its deadline disappears.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	receipt, err := s.Workflows.ApplyLifecycleReconciliation(ctx, plan)
	if err != nil {
		failReconciliation(w, err, false)
		return
	}
	writeReconciliationMetadata(w, receipt, 64<<10)
}
