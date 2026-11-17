//go:build windows

package engine

import "os"

func openConfigInput(path string) (*os.File, error) { return openPreviewInput(path) }
