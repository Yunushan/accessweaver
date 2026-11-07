//go:build !windows && !linux && !darwin && !freebsd && !openbsd

package engine

import "os"

func openConfigInput(path string) (*os.File, error) { return os.Open(path) }
