package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

type reconciliationCLIBackend struct {
	calls                             []string
	selections                        []workflow.LifecycleReconciliationRequest
	plan                              workflow.LifecycleReconciliationPlan
	receipt                           workflow.LifecycleReconciliationReceipt
	previewErr, errorApply, errorRead error
	applied                           string
}

func (b *reconciliationCLIBackend) LifecycleReconciliationStatus(context.Context) (workflow.LifecycleReconciliationStatus, error) {
	b.calls = append(b.calls, "status")
	return workflow.LifecycleReconciliationStatus{State: "none", Scope: "original-local-owners-only", Protection: "retirement-unavailable"}, b.errorRead
}
func (b *reconciliationCLIBackend) PreviewLifecycleReconciliation(_ context.Context, r workflow.LifecycleReconciliationRequest) (workflow.LifecycleReconciliationPlan, error) {
	b.calls = append(b.calls, "preview")
	b.selections = append(b.selections, r)
	return b.plan, b.previewErr
}
func (b *reconciliationCLIBackend) ApplyLifecycleReconciliation(_ context.Context, id string) (workflow.LifecycleReconciliationReceipt, error) {
	b.calls = append(b.calls, "apply")
	b.applied = id
	return b.receipt, b.errorApply
}
func (b *reconciliationCLIBackend) ReadLifecycleReconciliationReceipt(_ context.Context, id string) (workflow.LifecycleReconciliationReceipt, error) {
	b.calls = append(b.calls, "receipt:"+id)
	return b.receipt, b.errorRead
}

func newReconciliationCLIBackend() *reconciliationCLIBackend {
	generation, operation, plan := strings.Repeat("a", 48), strings.Repeat("b", 48), strings.Repeat("c", 48)
	return &reconciliationCLIBackend{
		plan:    workflow.LifecycleReconciliationPlan{ID: plan, OperationID: operation, Generation: generation, ReviewRevision: strings.Repeat("1", 64), Action: "retry-local-release-ack", ExpiresAt: time.Now().Add(time.Minute).UTC(), Resume: true, Scope: "original-local-owners-only", Protection: "retirement-unavailable", Objects: []workflow.LifecycleReconciliationObject{}},
		receipt: workflow.LifecycleReconciliationReceipt{OperationID: operation, Generation: generation, State: "completed", Action: "retry-local-release-ack", Scope: "original-local-owners-only", Protection: "retirement-unavailable", Quarantined: []workflow.LifecycleReconciliationObject{}, CompletedAt: time.Now().UTC()},
	}
}

func TestSystemHistoryReconciliationRejectsUnreviewedOrAmbiguousCommands(t *testing.T) {
	op, revision := strings.Repeat("b", 48), strings.Repeat("1", 64)
	cases := [][]string{
		{"status", "extra"}, {"status", "--force"}, {"receipt"}, {"receipt", "../../private"}, {"receipt", op, "extra"},
		{"preview", "--generation"}, {"preview", "--generation", strings.Repeat("A", 48)}, {"preview", "--operation", op, "--generation", op}, {"preview", "--force", op},
		{"apply", op}, {"apply", op, "--confirm"}, {"apply", op, "--review-revision", revision}, {"apply", op, "--review-revision", revision, "--force"},
		{"apply", op, "--review-revision", revision, "--confirm", "--confirm"}, {"apply", op, "--review-revision", strings.Repeat("A", 64), "--confirm"}, {"apply", op, "--confirm", "--confirm", "--confirm"},
		{"unknown"},
	}
	for _, args := range cases {
		backend := newReconciliationCLIBackend()
		var output bytes.Buffer
		err := runSystemReconciliation(context.Background(), backend, args, &output)
		if !errors.Is(err, workflow.ErrLifecycleReconciliationInvalidRequest) || len(backend.calls) != 0 || output.Len() != 0 {
			t.Fatal("invalid reconciliation command reached backend or printed a result")
		}
	}
}

func TestSystemHistoryReconciliationFreshReviewedResumeUsesSameManager(t *testing.T) {
	for _, confirmFirst := range []bool{false, true} {
		backend := newReconciliationCLIBackend()
		var output bytes.Buffer
		args := []string{"apply", backend.plan.OperationID, "--review-revision", backend.plan.ReviewRevision, "--confirm"}
		if confirmFirst {
			args = []string{"apply", backend.plan.OperationID, "--confirm", "--review-revision", backend.plan.ReviewRevision}
		}
		if err := runSystemReconciliation(context.Background(), backend, args, &output); err != nil {
			t.Fatal("confirmed exact resumed operation failed")
		}
		if strings.Join(backend.calls, ",") != "preview,apply" || len(backend.selections) != 1 || backend.selections[0].OperationID != backend.plan.OperationID || backend.selections[0].Generation != "" || backend.applied != backend.plan.ID {
			t.Fatal("CLI reused a foreign in-memory plan instead of the fresh exact reviewed resume")
		}
		var receipt workflow.LifecycleReconciliationReceipt
		if json.Unmarshal(output.Bytes(), &receipt) != nil || receipt.OperationID != backend.plan.OperationID || receipt.State != "completed" {
			t.Fatal("CLI failed to encode the actual resumed operation receipt")
		}
	}
}

func TestSystemHistoryReconciliationChangedReviewOrLiveOnlyPlanNeverApplies(t *testing.T) {
	for _, change := range []string{"revision", "operation", "live-only", "plan-id", "action", "scope", "protection"} {
		backend := newReconciliationCLIBackend()
		operation, revision := backend.plan.OperationID, backend.plan.ReviewRevision
		switch change {
		case "revision":
			backend.plan.ReviewRevision = strings.Repeat("2", 64)
		case "operation":
			backend.plan.OperationID = strings.Repeat("d", 48)
		case "live-only":
			backend.plan.Resume = false
		case "plan-id":
			backend.plan.ID = "../outside"
		case "action":
			backend.plan.Action = "delete"
		case "scope":
			backend.plan.Scope = "all-resources"
		case "protection":
			backend.plan.Protection = "retirement-allowed"
		}
		var output bytes.Buffer
		err := runSystemReconciliation(context.Background(), backend, []string{"apply", operation, "--review-revision", revision, "--confirm"}, &output)
		if !errors.Is(err, workflow.ErrLifecycleReconciliationConflict) || strings.Join(backend.calls, ",") != "preview" || output.Len() != 0 {
			t.Fatal("changed or unsupported reviewed material reached apply")
		}
	}
}

func TestSystemHistoryReconciliationErrorsRemainFixedAndRetainCauses(t *testing.T) {
	private := errors.New("PRIVATE_PATH_OR_PROFILE_DETAIL")
	for _, cause := range []error{managed.ErrDenied, managed.ErrUnavailable, workflow.ErrLifecycleReconciliationUnavailable, workflow.ErrLifecycleReconciliationPending, workflow.ErrLifecycleReconciliationConflict, workflow.ErrLifecycleReconciliationExpired} {
		backend := newReconciliationCLIBackend()
		backend.previewErr = errors.Join(cause, private)
		var output bytes.Buffer
		err := runSystemReconciliation(context.Background(), backend, []string{"preview"}, &output)
		if err == nil || !errors.Is(err, cause) || !errors.Is(err, private) || strings.Contains(err.Error(), "PRIVATE") || len(err.Error()) > 256 || output.Len() != 0 {
			t.Fatal("reconciliation CLI printed private failure detail or a fake successful result")
		}
	}
	backend := newReconciliationCLIBackend()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if err := runSystemReconciliation(ctx, backend, []string{"status"}, &output); !errors.Is(err, context.Canceled) || len(backend.calls) != 0 || output.Len() != 0 {
		t.Fatal("canceled CLI inspection reached backend or printed clean state")
	}
}

func TestSystemHistoryReconciliationReadCommandsAndDispatcher(t *testing.T) {
	generation, operation := strings.Repeat("a", 48), strings.Repeat("b", 48)
	for _, args := range [][]string{nil, {"status"}, {"preview"}, {"preview", "--generation", generation}, {"preview", "--operation", operation}, {"receipt", operation}} {
		backend := newReconciliationCLIBackend()
		var output bytes.Buffer
		if err := runSystemReconciliation(context.Background(), backend, args, &output); err != nil || !json.Valid(output.Bytes()) || len(backend.calls) != 1 {
			t.Fatal("readonly or explicit preview command failed its bounded dispatcher")
		}
	}
	root := filepath.Join(t.TempDir(), "absent-store")
	manager := workflow.New(root)
	var output bytes.Buffer
	if err := runSystemHistory(context.Background(), manager, []string{"reconciliation", "status"}, &output); err != nil {
		t.Fatal("real readonly CLI dispatcher failed on absent storage")
	}
	var status workflow.LifecycleReconciliationStatus
	if json.Unmarshal(output.Bytes(), &status) != nil || status.State != "none" || status.CanPreview || status.ResumeAvailable {
		t.Fatal("absent reconciliation evidence became permission")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("readonly reconciliation CLI initialized storage")
	}
}
