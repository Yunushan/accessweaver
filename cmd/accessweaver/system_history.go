package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/Yunushan/accessweaver/internal/privatefile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

type systemHistoryRequest struct {
	operation  string
	page       workflow.HistoryPageQuery
	ref        string
	revision   string
	outputPath string
}

func parseSystemHistory(args []string) (systemHistoryRequest, error) {
	var request systemHistoryRequest
	if len(args) == 0 {
		return request, nil
	}
	request.operation = args[0]
	switch args[0] {
	case "capture", "lifecycle":
		if len(args) != 1 {
			return request, workflow.ErrHistoryInvalidRequest
		}
	case "list":
		seen := make(map[string]bool)
		for i := 1; i < len(args); i += 2 {
			if i+1 >= len(args) || seen[args[i]] || args[i+1] == "" {
				return request, workflow.ErrHistoryInvalidRequest
			}
			seen[args[i]] = true
			switch args[i] {
			case "--limit":
				for _, digit := range args[i+1] {
					if digit < '0' || digit > '9' {
						return request, workflow.ErrHistoryInvalidRequest
					}
				}
				limit, err := strconv.Atoi(args[i+1])
				if err != nil || limit < 1 || limit > 128 {
					return request, workflow.ErrHistoryInvalidRequest
				}
				request.page.Limit = limit
			case "--cursor":
				if !systemHistoryOpaque(args[i+1]) {
					return request, workflow.ErrHistoryInvalidRequest
				}
				request.page.Cursor = args[i+1]
			case "--snapshot":
				if !systemHistoryHex(args[i+1], 48) {
					return request, workflow.ErrHistoryInvalidRequest
				}
				request.page.Snapshot = args[i+1]
			default:
				return request, workflow.ErrHistoryInvalidRequest
			}
		}
	case "get", "export":
		if (len(args) != 4 && !(args[0] == "export" && len(args) == 6)) || args[2] != "--revision" || !systemHistoryOpaque(args[1]) || !(systemHistoryHex(args[3], 64) || args[0] == "get" && args[3] == "") {
			return request, workflow.ErrHistoryInvalidRequest
		}
		request.ref, request.revision = args[1], args[3]
		if len(args) == 6 {
			if args[4] != "--out" || args[5] == "" || strings.HasPrefix(args[5], "--") {
				return request, workflow.ErrHistoryInvalidRequest
			}
			request.outputPath = args[5]
		}
	default:
		return request, workflow.ErrHistoryInvalidRequest
	}
	return request, nil
}

func systemHistoryHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, digit := range value {
		if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f') {
			return false
		}
	}
	return true
}

func systemHistoryOpaque(value string) bool {
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

type systemHistoryFailure struct {
	message string
	cause   error
}

func (e *systemHistoryFailure) Error() string { return e.message }
func (e *systemHistoryFailure) Unwrap() error { return e.cause }

func systemHistoryError(err error) error {
	if err == nil {
		return nil
	}
	message := workflow.ErrHistoryUnavailable.Error()
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		message = "workflow history request ended before completion"
	case errors.Is(err, workflow.ErrWorkflowLifecyclePending):
		message = workflow.ErrWorkflowLifecyclePending.Error()
	case errors.Is(err, workflow.ErrWorkflowLifecycle):
		message = workflow.ErrWorkflowLifecycle.Error()
	case errors.Is(err, workflow.ErrHistoryInvalidRequest):
		message = workflow.ErrHistoryInvalidRequest.Error()
	case errors.Is(err, workflow.ErrHistoryInventoryNeeded):
		message = workflow.ErrHistoryInventoryNeeded.Error()
	case errors.Is(err, workflow.ErrHistoryInventoryStale):
		message = workflow.ErrHistoryInventoryStale.Error()
	case errors.Is(err, workflow.ErrHistoryRecordUnavailable):
		message = workflow.ErrHistoryRecordUnavailable.Error()
	case errors.Is(err, workflow.ErrHistoryCapacity):
		message = workflow.ErrHistoryCapacity.Error()
	case errors.Is(err, workflow.ErrWorkflowBusy):
		message = workflow.ErrWorkflowBusy.Error()
	}
	return &systemHistoryFailure{message: message, cause: err}
}

// This private caller-context/writer seam is used by the actual CLI dispatcher.
// New commands never change global stdout or need a second Manager protocol.
func runSystemHistory(ctx context.Context, manager *workflow.Manager, args []string, output io.Writer) error {
	if len(args) > 0 && args[0] == "reconciliation" {
		return runSystemReconciliation(ctx, manager, args[1:], output)
	}
	request, err := parseSystemHistory(args)
	if err != nil {
		return systemHistoryError(err)
	}
	out := systemHistoryWriter{ctx: ctx, out: output}
	if request.operation == "" {
		// Preserve the complete legacy full-array format and legacy error API.
		items, err := manager.HistoryContext(ctx)
		if err != nil {
			return err
		}
		return workflow.WriteHistoryJSON(out, items)
	}
	if err := ctx.Err(); err != nil {
		return systemHistoryError(err)
	}
	switch request.operation {
	case "lifecycle":
		status, err := manager.LifecycleStatus(ctx)
		if err != nil {
			return systemHistoryError(err)
		}
		return systemHistoryError(writeSystemHistoryMetadata(out, status))
	case "capture":
		inventory, err := manager.CaptureHistoryInventory(ctx)
		if err != nil {
			return systemHistoryError(err)
		}
		return systemHistoryError(writeSystemHistoryMetadata(out, inventory))
	case "list":
		page, err := manager.HistoryPage(ctx, request.page)
		if err != nil {
			return systemHistoryError(err)
		}
		return systemHistoryError(writeSystemHistoryMetadata(out, page))
	case "get":
		detail, err := manager.ReadHistoryRecord(ctx, request.ref, request.revision)
		if err != nil {
			return systemHistoryError(err)
		}
		return systemHistoryError(workflow.WriteHistoryRecordDetailJSON(out, detail))
	case "export":
		data, err := manager.ReadHistoryRecordRaw(ctx, request.ref, request.revision)
		if err != nil {
			return systemHistoryError(err)
		}
		if request.outputPath != "" {
			if err := writeSystemHistoryExportFile(ctx, request.outputPath, data); err != nil {
				return &systemHistoryFailure{message: "workflow history export could not be written; preserve any partial output", cause: err}
			}
			return nil
		}
		_, err = out.Write(data)
		return systemHistoryError(err)
	}
	return systemHistoryError(workflow.ErrHistoryInvalidRequest)
}

func writeSystemHistoryMetadata(out io.Writer, value any) error {
	// Only the fixed inventory and bounded page metadata types use this encoder.
	// Full Job/Result and exact raw bytes use their own streaming paths.
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	_, err = out.Write(encoded)
	return err
}

type systemHistoryWriter struct {
	ctx context.Context
	out io.Writer
}

func (w systemHistoryWriter) Write(data []byte) (int, error) {
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

// Export files bypass shell stdout text conversion. Create only after the
// selected source/revision has been validated, and never replace a destination.
func writeSystemHistoryExportFile(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := privatefile.Create(path)
	if err != nil {
		return err
	}
	return finishSystemHistoryExport(ctx, file, data)
}

type systemHistoryExportStream interface {
	io.Writer
	Sync() error
	Close() error
}

// A caller-owned stream keeps the physical file path and synthetic test faults
// in the same write/sync/close composition. A failed partial is never removed.
func finishSystemHistoryExport(ctx context.Context, file systemHistoryExportStream, data []byte) error {
	_, err := (systemHistoryWriter{ctx: ctx, out: file}).Write(data)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = ctx.Err()
	}
	return errors.Join(err, file.Close())
}
