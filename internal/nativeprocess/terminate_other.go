//go:build !windows

package nativeprocess

import (
	"os"
	"os/exec"
)

func configureTerminator(cmd *exec.Cmd) {}

// Tree ownership is Windows-specific. Other production platforms fail closed;
// protocol tests can supply only a private per-instance fake backend.
type unsupportedTreeBackend struct{}

func newTreeBackend() treeBackend { return unsupportedTreeBackend{} }
func (unsupportedTreeBackend) withHandle(*os.Process, func(uintptr)) error {
	return ErrTreeOwnerUnavailable
}
func (unsupportedTreeBackend) duplicate(uintptr) (uintptr, error) { return 0, ErrTreeOwnerUnavailable }
func (unsupportedTreeBackend) processID(uintptr) (int, error)     { return 0, ErrTreeOwnerUnavailable }
func (unsupportedTreeBackend) terminate(uintptr) error            { return ErrTreeOwnerUnavailable }
func (unsupportedTreeBackend) close(uintptr) error                { return ErrTreeOwnerUnavailable }
func (unsupportedTreeBackend) tree(uintptr, int) error            { return ErrTreeOwnerUnavailable }
