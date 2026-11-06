//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"errors"
	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"os"
)

// Only per-call in-package fixtures supply completion cofactors. Production
// always constructs these operations here; owner, group, filesystem, paths,
// payload seals and native inspection operations have no fixture overrides.
type runtimeReadOps struct {
	closeFile  func(*os.File) error
	closeLease func(*RuntimeLease) error
}

func nativeRuntimeReads() runtimeReadOps {
	return runtimeReadOps{closeFile: (*os.File).Close, closeLease: (*RuntimeLease).Close}
}
func (r runtimeReadOps) finish(file *os.File, body error) error {
	if file == nil {
		return body
	}
	if closed := r.closeFile(file); closed != nil {
		return errors.Join(darwintrust.ErrReadCleanupUncertain, body, closed)
	}
	return body
}
func (r runtimeReadOps) finishLease(lease *RuntimeLease, body error) error {
	if lease == nil {
		return body
	}
	if closed := r.closeLease(lease); closed != nil {
		return errors.Join(darwintrust.ErrReadCleanupUncertain, body, closed)
	}
	return body
}

// Parent ownership transfers on entry. Metadata closes while the shared lease
// is still held; only a completely verified, completely closed metadata scope
// transfers its lease. Failure and panic both dispose of the acquired lease.
func acquireInstalledRuntimeScope(parent *os.File, r runtimeReadOps, verify func(*os.File, *RuntimeLease) error) (lease *RuntimeLease, failure error) {
	var root *os.File
	completed := false
	defer func() {
		failure = r.finish(root, failure)
		failure = r.finish(parent, failure)
		if !completed || failure != nil {
			failure = r.finishLease(lease, failure)
			lease = nil
		}
	}()
	var err error
	root, err = r.deploymentDirectory(parent, deploymentRoot, 0, false)
	if err != nil {
		return nil, err
	}
	lease, err = r.acquireRuntimeReader(root)
	if err != nil {
		return lease, err
	}
	failure = verify(root, lease)
	completed = true
	return lease, failure
}
