//go:build !windows

package workflow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkflowControllerStorageStatusRejectsSymlinkedEmptyComponent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "owned-empty-fixture")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal("source fixture unavailable")
	}
	if err := os.Symlink(target, filepath.Join(root, controllerStorageDirectory)); err != nil {
		t.Fatal("source fixture symlink unavailable")
	}
	status, err := New(root).ControllerStorageStatus(context.Background())
	if !errors.Is(err, ErrWorkflowStoragePending) || status.State != "pending" {
		t.Fatal("read-only status followed a symlinked storage component")
	}
}
