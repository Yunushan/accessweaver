//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"errors"
	"os"
)

// ErrDeploymentCleanupUncertain reports unconfirmed completion of an owned
// deployment descriptor. A published record remains published; callers must
// inspect/reconcile instead of undoing or blindly repeating the operation.
var ErrDeploymentCleanupUncertain = errors.New("deployment cleanup could not be confirmed")

// Only in-package fixtures supply a per-call completion cofactor. This is not
// a creator, path, owner, ACL, quota, sync, write or authorization override.
type deploymentCompletion struct{ closeFile func(*os.File) error }

func nativeDeploymentCompletion() deploymentCompletion {
	return deploymentCompletion{closeFile: (*os.File).Close}
}
func (d deploymentCompletion) finish(file *os.File, prior error) error {
	if file == nil {
		return prior
	}
	if closed := d.closeFile(file); closed != nil {
		return errors.Join(ErrDeploymentCleanupUncertain, prior, closed)
	}
	return prior
}

func (s *deploymentStore) closeWith(d deploymentCompletion) error {
	s.closeOnce.Do(func() {
		// Keep both coordination locks through every non-lock descriptor close.
		// Release locks last, in reverse acquisition order. Never retry a native
		// Close after an ambiguous outcome; retain the first result for all callers.
		for _, owned := range []**os.File{&s.current, &s.versions, &s.root, &s.parent, &s.runtimeLock, &s.lock} {
			file := *owned
			*owned = nil
			s.closeErr = d.finish(file, s.closeErr)
		}
	})
	return s.closeErr
}
