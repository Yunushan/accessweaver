package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func systemCommand(args []string, root string) error {
	manager := workflow.New(root)
	if len(args) == 0 {
		fmt.Print("Windows system workflows:\n  system operations\n  system presets\n  system discover\n  system preview REQUEST.json\n  system apply REQUEST.json --confirm\n  system storage [status]\n  system history\n  system history lifecycle\n  system history reconciliation [status|preview|receipt|apply] ...\n  system history capture\n  system history list [--limit N] [--cursor CURSOR] [--snapshot SNAPSHOT]\n  system history get REF --revision REV\n  system history export REF --revision REV [--out PATH]\nRequest format and recovery: docs/WINDOWS_WORKFLOWS.md\n")
		return nil
	}
	switch args[0] {
	case "check-version":
		if len(args) < 2 || len(args) > 65 {
			return errors.New("usage: system check-version TAG [TAG...]")
		}
		check, err := workflow.CheckVersions(buildinfo.Version, args[1:])
		if err != nil {
			return err
		}
		return printJSON(check)
	case "operations":
		return printJSON(workflow.Catalog())
	case "presets":
		items, err := workflow.Presets()
		if err != nil {
			return err
		}
		return printJSON(items)
	case "storage":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runSystemControllerStorage(ctx, manager, args[1:], os.Stdout)
	case "history":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runSystemHistory(ctx, manager, args[1:], os.Stdout)
	case "parse-scan":
		if len(args) != 3 {
			return errors.New("usage: system parse-scan REPORT.txt zapret|zapret2")
		}
		file, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
		if err != nil {
			return err
		}
		strategy, err := workflow.SelectScanStrategy(string(data), args[2])
		if err != nil {
			return err
		}
		return printJSON(strategy)
	case "discover", "preview", "apply":
		var request workflow.Request
		if args[0] == "discover" {
			request.Action = "discover"
		} else {
			if len(args) < 2 {
				return errors.New("provide a JSON workflow request file")
			}
			file, err := os.Open(args[1])
			if err != nil {
				return err
			}
			defer file.Close()
			data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
			if err != nil {
				return err
			}
			if len(data) > 1<<20 {
				return errors.New("workflow request exceeds 1 MiB")
			}
			// Windows PowerShell's UTF8 encoding includes a BOM.
			dec := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&request); err != nil {
				return err
			}
			var rest any
			if err := dec.Decode(&rest); err != io.EOF {
				return errors.New("expected one workflow JSON object")
			}
		}
		plan, err := manager.Preview(request)
		if err != nil {
			return err
		}
		if args[0] == "preview" {
			return printJSON(plan)
		}
		if args[0] == "apply" && (len(args) != 3 || args[2] != "--confirm") {
			return errors.New("preview the request, then use system apply REQUEST.json --confirm")
		}
		restoreOutput := observeAuditOutputPipes()
		defer restoreOutput()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err = manager.Start(plan.ID); err != nil {
			return err
		}
		return waitSystemWorkflow(ctx, manager, 8*time.Second, func(job workflow.Job) error { return workflow.WriteJobJSON(os.Stdout, job) })

	default:
		return errors.New("unknown system command")
	}
}

type systemWorkflow interface {
	Snapshot() workflow.Job
	Shutdown(context.Context) error
	TerminalError(string) error
}

// Cancellation retains the manager through its terminal history write. The
// bounded diagnostic wait never permits abandoning a reserved or active job.
func waitSystemWorkflow(ctx context.Context, manager systemWorkflow, shutdownTimeout time.Duration, emit func(workflow.Job) error) error {
	return waitSystemWorkflowWithFeedback(ctx, manager, shutdownTimeout, emit, os.Stderr)
}

func waitSystemWorkflowWithFeedback(ctx context.Context, manager systemWorkflow, shutdownTimeout time.Duration, emit func(workflow.Job) error, feedback io.Writer) error {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return cancelSystemWorkflowWithFeedback(ctx, manager, shutdownTimeout, emit, feedback)
		}
		job := manager.Snapshot()
		if job.State != "running" {
			return errors.Join(emit(job), systemWorkflowTerminalError(manager, job))
		}
		select {
		case <-ctx.Done():
			return cancelSystemWorkflowWithFeedback(ctx, manager, shutdownTimeout, emit, feedback)
		case <-ticker.C:
		}
	}
}

var errSystemShutdownOutput = errors.New("workflow shutdown notice could not be written")

func cancelSystemWorkflow(ctx context.Context, manager systemWorkflow, timeout time.Duration, emit func(workflow.Job) error) error {
	return cancelSystemWorkflowWithFeedback(ctx, manager, timeout, emit, os.Stderr)
}

func cancelSystemWorkflowWithFeedback(ctx context.Context, manager systemWorkflow, timeout time.Duration, emit func(workflow.Job) error, feedback io.Writer) error {
	initial, cancel := context.WithTimeout(context.Background(), timeout)
	initialErr := manager.Shutdown(initial)
	var outputErr error
	if initial.Err() != nil && errors.Is(initialErr, initial.Err()) && manager.Snapshot().State == "running" {
		const notice = "Workflow shutdown is not confirmed. Waiting for the owned job and final status record; keep this command active.\n"
		if n, err := io.WriteString(feedback, notice); err != nil || n != len(notice) {
			outputErr = errSystemShutdownOutput
		}
	}
	cancel()
	// The background join observes the same captured generation and cached
	// result. Diagnostic cancellation or a failed notice cannot release it.
	finalErr := manager.Shutdown(context.Background())
	job := manager.Snapshot()
	if finalErr == nil {
		finalErr = systemWorkflowTerminalError(manager, job)
	}
	return errors.Join(errors.New("workflow cancellation requested; inspect the recorded outcome and recovery journal before retrying"), ctx.Err(), finalErr, emit(job), outputErr)
}

// Exact current-job lookup preserves typed failures even when the job finished
// before shutdown began. The display fallback describes plain cooperative
// cancellation; it is never used to reconstruct a retained failure category.
func systemWorkflowTerminalError(manager systemWorkflow, job workflow.Job) error {
	if err := manager.TerminalError(job.ID); err != nil {
		return err
	}
	return systemJobError(job)
}

func systemJobError(job workflow.Job) error {
	if job.State == "succeeded" {
		return nil
	}
	if job.Error != "" {
		return errors.New(job.Error)
	}
	return fmt.Errorf("workflow ended in state %q without a successful result", job.State)
}
