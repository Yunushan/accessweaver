package packageupgrade

import (
	"os"
	"sync"
)

const runtimeLeaseName = ".runtime.lock"
const runtimeLeaseEnvironment = "ACCESSWEAVER_RUNTIME_LEASE_FD"

// RuntimeLease coordinates an installed process with deployment mutations. It
// is advisory concurrency control, not authorization or a general process
// sandbox. Hold it until controller shutdown and profile locks have completed.
type RuntimeLease struct {
	file     *os.File
	close    sync.Once
	closeErr error
}

func (l *RuntimeLease) Close() error {
	if l == nil {
		return nil
	}
	l.close.Do(func() {
		if l.file != nil {
			l.closeErr = l.file.Close()
		}
	})
	return l.closeErr
}
