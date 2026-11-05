//go:build !windows && !linux && !darwin && !freebsd && !openbsd

package engine

func newExitObserver() (exitObserver, error) { return nil, ErrProcessLifecycle }
