package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

var (
	ErrProcessCleanupPending = errors.New("engine process cleanup is unresolved")
	ErrProcessOwnershipLost  = errors.New("engine process ownership is unavailable")
	ErrProcessLifecycle      = errors.New("engine process lifetime was not fully observed")
)

// Each launch retains this owner until real process and I/O completion. A
// caller abandoning its wait cannot abandon the owner's native operations.
type processLifetime interface {
	dispatch(func(*os.Process) error) error
	wait(context.Context) (error, error)
	pendingError() error
	faultSignal() <-chan struct{}
	retryCleanup() error
	setFaultHandler(func(error))
	abortStart() error
}

type lifetimeFactory func(*exec.Cmd) (processLifetime, error)
