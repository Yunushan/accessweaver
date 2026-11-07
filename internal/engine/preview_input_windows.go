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

func statPreviewInput(path string) (os.FileInfo, error) {
	file, err := openPreviewInput(path)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil {
		return nil, fileidentity.ErrUnavailable
	}
	return info, nil
}

func lookupPreviewExecutable(ctx context.Context, name string) (string, error) {
	found := searchWindowsPreviewExecutable(ctx, name, filepath.SplitList(os.Getenv("PATH")), func(path string) bool {
		info, err := statPreviewInput(path)
		return err == nil && info.Mode().IsRegular()
	})
	if err := preparationContextError(ctx); err != nil {
		return "", err
	}
	if found == "" {
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	return found, nil
}
