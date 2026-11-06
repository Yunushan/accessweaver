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

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func TestSystemControllerStorageReadOnlyAndClosedArguments(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	manager := workflow.NewWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	for _, args := range [][]string{nil, {"status"}} {
		var out bytes.Buffer
		if err := runSystemControllerStorage(context.Background(), manager, args, &out); err != nil {
			t.Fatal("readonly controller status unavailable")
		}
		var value workflow.ControllerStorageStatus
		if out.Len() > 4096 || json.Unmarshal(out.Bytes(), &value) != nil || value.State != "uninitialized" || value.LegacyAccounting != "not-included" || value.Scope != "tracked-controller-evidence-only" || value.AggregateQuotaEnforced || value.PhysicalCapacityGuaranteed || value.NativeWritersContained || value.WorkerJournalBounded {
			t.Fatal("CLI status invented a quota or legacy usage")
		}
	}
	for _, args := range [][]string{{"force"}, {"status", "--force"}, {"capture"}, {"status", "--generation", strings.Repeat("a", 48)}} {
		var out bytes.Buffer
		if err := runSystemControllerStorage(context.Background(), manager, args, &out); err == nil || out.Len() != 0 {
			t.Fatal("CLI accepted mutation/unreviewed status arguments")
		}
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("CLI readonly/invalid status initialized storage")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := runSystemControllerStorage(ctx, manager, nil, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("ended status context wrote metadata")
	}
}
func TestSystemControllerStorageErrorsPreserveCausesWithoutPrivateText(t *testing.T) {
	private := errors.New("PRIVATE_CONTROLLER_STORAGE")
	for _, category := range []error{workflow.ErrWorkflowStorageCapacity, workflow.ErrWorkflowStoragePending, workflow.ErrWorkflowBusy, workflow.ErrWorkflowStore, managed.ErrDenied, managed.ErrUnavailable, context.Canceled} {
		err := systemControllerStorageError(errors.Join(category, private))
		if !errors.Is(err, category) || !errors.Is(err, private) || strings.Contains(err.Error(), "PRIVATE_") {
			t.Fatal("CLI storage status lost cause or leaked private text")
		}
	}
	if systemControllerStorageError(nil) != nil {
		t.Fatal("successful status became failure")
	}
}
