package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func systemControllerStorageError(err error) error {
	if err == nil {
		return nil
	}
	message := "controller storage accounting is unavailable; preserve existing evidence"
	switch {
	case errors.Is(err, managed.ErrDenied):
		message = "controller storage inspection is not permitted by the current policy"
	case errors.Is(err, managed.ErrUnavailable):
		message = "controller storage policy is unavailable"
	case errors.Is(err, workflow.ErrWorkflowBusy):
		message = "controller storage inspection is busy; try again shortly"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		message = "controller storage request ended before completion"
	case errors.Is(err, workflow.ErrHistoryInvalidRequest):
		message = "invalid controller storage status command"
	case errors.Is(err, workflow.ErrWorkflowStorageCapacity):
		message = workflow.ErrWorkflowStorageCapacity.Error()
	case errors.Is(err, workflow.ErrWorkflowStoragePending):
		message = workflow.ErrWorkflowStoragePending.Error()
	}
	return &systemHistoryFailure{message: message, cause: err}
}
func runSystemControllerStorage(ctx context.Context, manager *workflow.Manager, args []string, output io.Writer) error {
	if len(args) > 1 || len(args) == 1 && args[0] != "status" {
		return systemControllerStorageError(workflow.ErrHistoryInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return systemControllerStorageError(err)
	}
	value, err := manager.ControllerStorageStatus(ctx)
	if err != nil {
		return systemControllerStorageError(err)
	}
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > 4096 {
		return systemControllerStorageError(errors.New("controller storage status encoding unavailable"))
	}
	_, err = (systemHistoryWriter{ctx: ctx, out: output}).Write(append(data, '\n'))
	return systemControllerStorageError(err)
}
