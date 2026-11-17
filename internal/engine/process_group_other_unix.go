//go:build !darwin && !windows

package engine

func groupSignalAlreadyExited(_ int, _ error) bool { return false }
