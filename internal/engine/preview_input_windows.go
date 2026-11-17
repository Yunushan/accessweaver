//go:build windows

package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
)

func openPreviewInput(path string) (*os.File, error) {
	if !windowsPreviewDrivePath(path) {
		return nil, fileidentity.ErrUnavailable
	}
	return fileidentity.OpenLocal(path)
}

func statPreviewInput(path string) (previewInputMetadata, error) {
	if !windowsPreviewDrivePath(path) {
		return previewInputMetadata{}, fileidentity.ErrUnavailable
	}
	state, err := fileidentity.FromPath(path, true)
	if err != nil {
		return previewInputMetadata{}, err
	}
	return previewInputMetadata{regular: state.Kind == fileidentity.Regular, size: state.Size}, nil
}

func lookupPreviewExecutable(ctx context.Context, name string) (string, error) {
	found := searchWindowsPreviewExecutable(ctx, name, filepath.SplitList(os.Getenv("PATH")), func(path string) bool {
		info, err := statPreviewInput(path)
		return err == nil && info.regular
	})
	if err := preparationContextError(ctx); err != nil {
		return "", err
	}
	if found == "" {
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	return found, nil
}
