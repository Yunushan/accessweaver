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
		fmt.Print("Windows system workflows:\n  system operations\n  system presets\n  system discover\n  system preview REQUEST.json\n  system apply REQUEST.json --confirm\n  system history\nRequest format and recovery: docs/WINDOWS_WORKFLOWS.md\n")
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
	case "history":
		items, err := manager.History()
		if err != nil {
			return err
		}
		return printJSON(items)
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
		if _, err = manager.Start(plan.ID); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				manager.Cancel()
				return errors.New("workflow cancelled; inspect the recovery journal before retrying")
			case <-ticker.C:
				job := manager.Snapshot()
				if job.State != "running" {
					if err := printJSON(job); err != nil {
						return err
					}
					if job.State != "succeeded" {
						return errors.New(job.Error)
					}
					return nil
				}
			}
		}
	default:
		return errors.New("unknown system command")
	}
}
