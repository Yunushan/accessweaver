//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

func removalArchiveName(fence removalFence) string {
	return ".AccessWeaver-removed-" + strings.TrimPrefix(fence.DisplacedRecord, ".record-")
}

// finalizeRemovalUsing is private until the whole removal transaction can run
// under a verified Apple Installer exclusion boundary. Both sets of leases
// stay held through an atomic exchange. The displaced authority is retained
// intact under a non-product path on the same protected parent.
func (r *removalIntentStore) finalizeRemovalUsing(ctx context.Context, resolve removalParentResolver) (published bool, result error) {
	if r == nil || r.store == nil || r.store.owner != 0 || r.store.current == nil || r.store.runtimeLock == nil || resolve == nil {
		return false, errors.New("removal handoff requires an open root intent")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	s := r.store
	if e := r.syncRemovalBarrier(); e != nil {
		return false, e
	}
	if e := r.requirePublicQuarantine(ctx, resolve); e != nil {
		return false, e
	}
	record, e := r.verifyCompletedRemoval(ctx, resolve)
	if e != nil {
		return false, e
	}
	name := removalArchiveName(r.fence)
	root, e := deploymentDirectory(s.parent, name, 0, false)
	if darwintrust.IsReadAbsent(e) {
		root, e = s.stageRemovalHandoff(name, record)
	}
	if e != nil {
		return false, e
	}
	next := &deploymentStore{root: root}
	defer func() { result = errors.Join(result, next.Close()) }()
	if e = next.lockRemovalHandoff(); e != nil {
		return false, e
	}
	if e = next.checkRemovalHandoff(record); e != nil {
		return false, e
	}
	// Re-sync the reservation even on retry. At this name only an exact clean
	// authority is eligible for exchange, regardless of how the attempt ended.
	if e = fullDeploymentSync(s.parent); e != nil {
		return false, e
	}
	if e = s.phase("removal-handoff-reserved"); e != nil {
		return false, e
	}
	if _, e = r.verifyCompletedRemoval(ctx, resolve); e != nil {
		return false, e
	}
	if e = next.checkRemovalHandoff(record); e != nil {
		return false, e
	}
	if e = sameDeploymentEntry(s.parent, name, root, 0); e != nil {
		return false, e
	}
	if e = s.checkRoot(); e != nil {
		return false, e
	}
	if ctx.Err() != nil {
		return false, errors.New("removal handoff deadline exceeded")
	}
	if e = darwintrust.RenameDirectories(s.parent, name, deploymentRoot, true); e != nil {
		return false, e
	}
	if e = s.phase("removal-handoff-exchanged"); e != nil {
		return true, e
	}
	if e = fullDeploymentSync(s.parent); e != nil {
		return true, e
	}
	if e = sameDeploymentEntry(s.parent, name, s.root, 0); e != nil {
		return true, e
	}
	return true, sameDeploymentEntry(s.parent, deploymentRoot, root, 0)
}

func (s *deploymentStore) stageRemovalHandoff(name string, record []byte) (result *os.File, failure error) {
	preparation, e := s.openRemovalPreparationDirectory()
	if e != nil {
		return nil, e
	}
	defer func() {
		failure = errors.Join(failure, preparation.Close())
		if failure != nil && result != nil {
			failure = errors.Join(failure, result.Close())
			result = nil
		}
	}()
	nonce, e := randomDeploymentName()
	if e != nil {
		return nil, e
	}
	stagingName := ".record-" + nonce
	root, e := darwintrust.CreateDirectoryAt(preparation, stagingName, 0)
	if e != nil {
		return nil, e
	}
	defer func() {
		if result == nil {
			failure = errors.Join(failure, root.Close())
		}
	}()
	if e = root.Chown(0, 0); e != nil {
		return nil, e
	}
	for _, child := range []string{"state", "versions"} {
		dir, e := deploymentDirectory(root, child, 0, true)
		if e != nil {
			return nil, e
		}
		if child == "state" {
			e = writeHandoffFile(dir, deploymentRecord, 0644, record)
		}
		if e = errors.Join(e, fullDeploymentSync(dir), dir.Close()); e != nil {
			return nil, e
		}
	}
	if e = writeHandoffFile(root, deploymentLock, 0600, nil); e != nil {
		return nil, e
	}
	if e = writeHandoffFile(root, runtimeLeaseName, 0644, nil); e != nil {
		return nil, e
	}
	if e = errors.Join(root.Chmod(0755), fullDeploymentSync(root), fullDeploymentSync(preparation)); e != nil {
		return nil, e
	}
	if e = sameDeploymentEntry(s.parent, removalPreparationRoot, preparation, 0); e != nil {
		return nil, e
	}
	if e = sameDeploymentEntry(preparation, stagingName, root, 0); e != nil {
		return nil, e
	}
	if e = darwintrust.RenameEntryNoReplace(preparation, stagingName, s.parent, name); e != nil {
		return nil, e
	}
	if e = fullDeploymentSync(preparation); e != nil {
		return nil, e
	}
	return root, nil
}

func writeHandoffFile(dir *os.File, name string, mode os.FileMode, data []byte) (result error) {
	file, e := darwintrust.CreateRegularAt(dir, name, 0)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	if e = file.Chown(0, 0); e != nil {
		return e
	}
	if n, e := file.Write(data); e != nil || n != len(data) {
		return errors.Join(e, io.ErrShortWrite)
	}
	return errors.Join(file.Chmod(mode), fullDeploymentSync(file))
}

func (s *deploymentStore) lockRemovalHandoff() error {
	var e error
	s.lock, e = darwintrust.OpenRegularAt(s.root, deploymentLock, 0)
	if e != nil {
		return e
	}
	if e = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return e
	}
	s.runtimeLock, e = runtimeFileAt(s.root, 0)
	if e != nil {
		return e
	}
	if e = unix.Flock(int(s.runtimeLock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return e
	}
	s.current, e = deploymentDirectory(s.root, "state", 0, false)
	if e != nil {
		return e
	}
	s.versions, e = deploymentDirectory(s.root, "versions", 0, false)
	return e
}

func (s *deploymentStore) checkRemovalHandoff(record []byte) error {
	if e := deploymentObject(s.root, true, 0, 0755); e != nil {
		return e
	}
	entries, e := deploymentEntries(s.root, 0, 4)
	if e != nil || len(entries) != 4 {
		return errors.Join(e, errors.New("removal handoff authority inventory differs"))
	}
	slots, e := deploymentEntries(s.versions, 0, 0)
	if e != nil || len(slots) != 0 {
		return errors.Join(e, errors.New("removal handoff versions are not empty"))
	}
	lock, e := darwintrust.OpenRegularAt(s.root, deploymentLock, 0)
	if e != nil {
		return e
	}
	actual, statErr := lock.Stat()
	e = errors.Join(statErr, deploymentObject(lock, false, 0, 0600), lock.Close())
	if e != nil {
		return e
	}
	held, e := s.lock.Stat()
	if e != nil {
		return e
	}
	if actual.Size() != 0 || !os.SameFile(actual, held) {
		return errors.New("removal handoff writer coordination differs")
	}
	raw, e := s.readRecord(s.current)
	if e != nil || !bytes.Equal(raw, record) {
		return errors.Join(e, errors.New("removal handoff inactive record differs"))
	}
	return errors.Join(
		sameRuntimeFile(s.root, s.runtimeLock, 0),
		sameDeploymentEntry(s.root, "state", s.current, 0),
		sameDeploymentEntry(s.root, "versions", s.versions, 0),
	)
}
