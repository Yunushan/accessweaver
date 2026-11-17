//go:build !windows

package engine

import (
	"context"
	"os"
	"os/exec"
)

func statPreviewInput(path string) (previewInputMetadata, error) {
	info, err := os.Stat(path)
	if err != nil {
		return previewInputMetadata{}, err
	}
	return previewInputMetadata{regular: info.Mode().IsRegular(), size: info.Size(), unixExecutable: info.Mode().Perm()&0111 != 0}, nil
}
func openPreviewInput(path string) (*os.File, error) { return os.Open(path) }
func lookupPreviewExecutable(ctx context.Context, name string) (string, error) {
	if err := preparationContextError(ctx); err != nil {
		return "", err
	}
	found, err := exec.LookPath(name)
	if canceled := preparationContextError(ctx, err); canceled != nil {
		return "", canceled
	}
	return found, err
}
