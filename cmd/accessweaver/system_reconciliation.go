package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

// The dispatcher passes the real Manager. This small command contract keeps
// reviewed-resume parsing independent from process/global stdout state.
type systemReconciliationBackend interface {
	LifecycleReconciliationStatus(context.Context) (workflow.LifecycleReconciliationStatus, error)
	PreviewLifecycleReconciliation(context.Context, workflow.LifecycleReconciliationRequest) (workflow.LifecycleReconciliationPlan, error)
	ApplyLifecycleReconciliation(context.Context, string) (workflow.LifecycleReconciliationReceipt, error)
	ReadLifecycleReconciliationReceipt(context.Context, string) (workflow.LifecycleReconciliationReceipt, error)
}

type systemReconciliationRequest struct {
	operation      string
	selection      workflow.LifecycleReconciliationRequest
	operationID    string
	reviewRevision string
}

func parseSystemReconciliation(args []string) (systemReconciliationRequest, error) {
	request := systemReconciliationRequest{operation: "status"}
	invalid := workflow.ErrLifecycleReconciliationInvalidRequest
	if len(args) == 0 {
		return request, nil
	}
	request.operation = args[0]
	switch request.operation {
	case "status":
		if len(args) != 1 {
			return request, invalid
		}
	case "receipt":
		if len(args) != 2 || !systemHistoryHex(args[1], 48) {
			return request, invalid
		}
		request.operationID = args[1]
	case "preview":
		if len(args) == 1 {
			return request, nil
		}
		if len(args) != 3 || !systemHistoryHex(args[2], 48) {
			return request, invalid
		}
		switch args[1] {
		case "--generation":
			request.selection.Generation = args[2]
		case "--operation":
			request.selection.OperationID = args[2]
		default:
			return request, invalid
		}
	case "apply":
		// A fresh CLI cannot reuse another process's in-memory plan or invent a
		// LIVE owner witness. It can explicitly resume already durable positive
		// proof after freshly reviewing precisely the material named by its digest.
		if len(args) != 5 || !systemHistoryHex(args[1], 48) {
			return request, invalid
		}
		request.operationID = args[1]
		confirm := false
		seen := map[string]bool{}
		for i := 2; i < len(args); i++ {
			if seen[args[i]] {
				return request, invalid
			}
			seen[args[i]] = true
			switch args[i] {
			case "--confirm":
				confirm = true
			case "--review-revision":
				i++
				if i >= len(args) || !systemHistoryHex(args[i], 64) {
					return request, invalid
				}
				request.reviewRevision = args[i]
			default:
				return request, invalid
			}
		}
		if !confirm || request.reviewRevision == "" {
			return request, invalid
		}
	default:
		return request, invalid
	}
	return request, nil
}

func systemReconciliationError(err error) error {
	if err == nil {
		return nil
	}
	message := "workflow reconciliation is unavailable; preserve its evidence"
	switch {
	case errors.Is(err, workflow.ErrLifecycleReconciliationInvalidRequest):
		message = workflow.ErrLifecycleReconciliationInvalidRequest.Error()
	case errors.Is(err, managed.ErrDenied):
		message = "workflow reconciliation is not permitted by the current policy"
	case errors.Is(err, managed.ErrUnavailable):
		message = "workflow reconciliation policy is unavailable"
	case errors.Is(err, workflow.ErrWorkflowBusy):
		message = workflow.ErrWorkflowBusy.Error()
	case errors.Is(err, workflow.ErrWorkflowStore):
		message = workflow.ErrWorkflowStore.Error()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		message = "workflow reconciliation request ended; inspect its known operation"
	case errors.Is(err, workflow.ErrLifecycleReconciliationConflict):
		message = workflow.ErrLifecycleReconciliationConflict.Error()
	case errors.Is(err, workflow.ErrLifecycleReconciliationExpired):
		message = workflow.ErrLifecycleReconciliationExpired.Error()
	case errors.Is(err, workflow.ErrLifecycleReconciliationPending):
		message = workflow.ErrLifecycleReconciliationPending.Error()
	case errors.Is(err, workflow.ErrLifecycleReconciliationUnavailable):
		message = workflow.ErrLifecycleReconciliationUnavailable.Error()
	}
	return &systemHistoryFailure{message: message, cause: err}
}

func writeSystemReconciliation(out io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > 64<<10 {
		return workflow.ErrLifecycleReconciliationUnavailable
	}
	data = append(data, '\n')
	_, err = out.Write(data)
	return err
}

func runSystemReconciliation(ctx context.Context, manager systemReconciliationBackend, args []string, output io.Writer) error {
	request, err := parseSystemReconciliation(args)
	if err != nil {
		return systemReconciliationError(err)
	}
	if err = ctx.Err(); err != nil {
		return systemReconciliationError(err)
	}
	out := systemHistoryWriter{ctx: ctx, out: output}
	switch request.operation {
	case "status":
		value, err := manager.LifecycleReconciliationStatus(ctx)
		if err != nil {
			return systemReconciliationError(err)
		}
		return systemReconciliationError(writeSystemReconciliation(out, value))
	case "preview":
		value, err := manager.PreviewLifecycleReconciliation(ctx, request.selection)
		if err != nil {
			return systemReconciliationError(err)
		}
		return systemReconciliationError(writeSystemReconciliation(out, value))
	case "receipt":
		value, err := manager.ReadLifecycleReconciliationReceipt(ctx, request.operationID)
		if err != nil {
			return systemReconciliationError(err)
		}
		return systemReconciliationError(writeSystemReconciliation(out, value))
	case "apply":
		plan, err := manager.PreviewLifecycleReconciliation(ctx, workflow.LifecycleReconciliationRequest{OperationID: request.operationID})
		if err != nil {
			return systemReconciliationError(err)
		}
		if !plan.Resume || plan.OperationID != request.operationID || plan.ReviewRevision != request.reviewRevision || !systemHistoryHex(plan.ID, 48) || !systemHistoryHex(plan.ReviewRevision, 64) || plan.Action != "retry-local-release-ack" || plan.Scope != "original-local-owners-only" || plan.Protection != "retirement-unavailable" {
			return systemReconciliationError(workflow.ErrLifecycleReconciliationConflict)
		}
		// This is the newly acquired, identity-bound plan on this SAME Manager.
		// Its own Apply rechecks expiry, policy and every exact object binding.
		receipt, err := manager.ApplyLifecycleReconciliation(ctx, plan.ID)
		if err != nil {
			return systemReconciliationError(err)
		}
		return systemReconciliationError(writeSystemReconciliation(out, receipt))
	}
	return systemReconciliationError(workflow.ErrLifecycleReconciliationInvalidRequest)
}
