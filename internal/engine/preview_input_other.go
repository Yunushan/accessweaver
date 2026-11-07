//go:build !windows

package engine

import (
	"context"
	"os"
	"os/exec"
)

func statPreviewInput(path string) (os.FileInfo, error) { return os.Stat(path) }
func openPreviewInput(path string) (*os.File, error)    { return os.Open(path) }
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
