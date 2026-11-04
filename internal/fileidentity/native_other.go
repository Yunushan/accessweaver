//go:build !windows && !linux && !darwin && !freebsd && !openbsd

package fileidentity

import "os"

// Unsupported native identity layouts refuse rather than inventing IDs from
// names, timestamps, or content. This fallback performs no filesystem access.
func fromFile(*os.File) (State, error)     { return State{}, ErrUnavailable }
func fromPath(string, bool) (State, error) { return State{}, ErrUnavailable }
