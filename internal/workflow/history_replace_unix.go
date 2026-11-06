//go:build !windows

package workflow

import "os"

func replaceHistoryIndex(source, destination string) error { return os.Rename(source, destination) }
