//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// The caller must hold the removal authority and exclude Installer for the
// whole operation. The private orchestrator leaves each interrupted action
// to the existing durable journal.
func (r *removalIntentStore) completeRemovalUsing(ctx context.Context, resolve removalParentResolver, forget func(context.Context, string) error) (bool, error) {
	if forget == nil {
		return false, errors.New("removal requires a receipt retirement tool")
	}
	if e := r.quarantinePublicAppUsing(ctx, resolve); e != nil {
		return false, e
	}
	actions, e := removalAllActions(r.plan)
	if e != nil {
		return false, e
	}
	_, _, journal, e := readRemovalJournalAt(r.store.current, 0, removalJournalSeed(r.fence), len(actions))
	if e != nil {
		return false, e
	}
	for completed := journal.completed; completed < len(actions); completed++ {
		scope := removalPayloadScope
		switch r.plan.Roots[actions[completed].root].Kind {
		case "registrations":
			scope = removalRegistrationScope
		case "receipts":
			scope = removalReceiptScope
		}
		// Payload scope covers the protected prefix and then the quarantined
		// application. Registration and receipt scopes enforce their own order.
		progress, e := r.removeNextRemovalObjectUsing(ctx, resolve, scope, forget)
		if e != nil {
			return false, e
		}
		if progress.completed != completed+1 {
			return false, errors.New("removal journal did not advance by one planned action")
		}
	}
	return r.finalizeRemovalUsing(ctx, resolve)
}

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
		root, e = s.stageRemovalHandoff(r.fence.DisplacedRecord, name, record)
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

func (s *deploymentStore) stageRemovalHandoff(stagingName, name string, record []byte) (result *os.File, failure error) {
	preparation, e := s.openRemovalPreparationDirectory(stagingName)
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
	// The reserved history name locates this intent's staging directory.
	// Repeated interruptions therefore consume at most one staging slot.
	root, e := darwintrust.OpenDirectoryAt(preparation, stagingName, 0)
	if darwintrust.IsReadAbsent(e) {
		root, e = darwintrust.CreateDirectoryAt(preparation, stagingName, 0)
		if e == nil {
			if e = root.Chown(0, 0); e != nil {
				return nil, errors.Join(e, root.Close())
			}
		}
	}
	if e != nil {
		return nil, e
	}
	defer func() {
		if result == nil {
			failure = errors.Join(failure, root.Close())
		}
	}()
	info, e := root.Stat()
	if e != nil {
		return nil, e
	}
	if info.Mode().Perm() != 0700 && info.Mode().Perm() != 0755 {
		return nil, errors.New("removal handoff staging permissions differ")
	}
	if e = deploymentObject(root, true, 0, info.Mode().Perm()); e != nil {
		return nil, e
	}
	entries, e := deploymentEntries(root, 0, 4)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "state", "versions", deploymentLock, runtimeLeaseName:
		default:
			return nil, errors.New("unknown removal handoff staging entry")
		}
	}
	for _, child := range []string{"state", "versions"} {
		dir, e := openHandoffStageDirectory(root, child)
		if e != nil {
			return nil, e
		}
		if child == "state" {
			var entries []os.DirEntry
			entries, e = deploymentEntries(dir, 0, 1)
			if e == nil {
				if len(entries) != 0 && entries[0].Name() != deploymentRecord {
					e = errors.New("unknown removal handoff state entry")
				} else {
					e = completeHandoffFile(dir, deploymentRecord, 0644, record)
				}
			}
		} else {
			_, e = deploymentEntries(dir, 0, 0)
		}
		if e == nil {
			e = fullDeploymentSync(dir)
		}
		if e = errors.Join(e, dir.Close()); e != nil {
			return nil, e
		}
		if child == "state" {
			if e = s.phase("removal-handoff-stage-record"); e != nil {
				return nil, e
			}
		}
	}
	if e = completeHandoffFile(root, deploymentLock, 0600, nil); e != nil {
		return nil, e
	}
	if e = completeHandoffFile(root, runtimeLeaseName, 0644, nil); e != nil {
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
	if e = errors.Join(fullDeploymentSync(preparation), fullDeploymentSync(s.parent)); e != nil {
		return nil, e
	}
	return root, nil
}

// A crash can leave a new staging directory in its initial mode.
func openHandoffStageDirectory(parent *os.File, name string) (*os.File, error) {
	dir, e := darwintrust.OpenDirectoryAt(parent, name, 0)
	if darwintrust.IsReadAbsent(e) {
		dir, e = darwintrust.CreateDirectoryAt(parent, name, 0)
	}
	if e != nil {
		return nil, e
	}
	info, e := dir.Stat()
	if e == nil {
		mode := info.Mode().Perm()
		if mode != 0700 && mode != 0755 {
			e = errors.New("removal handoff stage directory permissions differ")
		} else if e = deploymentObject(dir, true, 0, mode); e == nil && mode == 0700 {
			e = dir.Chmod(0755)
		}
	}
	if e != nil {
		return nil, errors.Join(e, dir.Close())
	}
	return dir, nil
}

// An interrupted write may leave an exact prefix at the named stage. Verify
// the original inode and append only its missing bytes. Refuse any other data.
func completeHandoffFile(dir *os.File, name string, mode os.FileMode, data []byte) (result error) {
	prefix, before, e := readAt(dir, name, int64(len(data)))
	var file *os.File
	if darwintrust.IsReadAbsent(e) {
		file, e = darwintrust.CreateRegularAt(dir, name, 0)
	} else if e == nil {
		permissions := os.FileMode(before.Mode & 07777)
		if !bytes.HasPrefix(data, prefix) ||
			permissions != 0600 && (permissions != mode || len(prefix) != len(data)) {
			return errors.New("removal handoff stage file differs")
		}
		var fd int
		fd, e = unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e == nil {
			file = os.NewFile(uintptr(fd), name)
		}
	}
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	actual, e := darwintrust.Check(file, false, 0)
	if e != nil {
		return e
	}
	st := *actual.Sys().(*syscall.Stat_t)
	if st.Gid != 0 || before.Ino != 0 && !sameState(st, before) {
		return errors.New("removal handoff stage file identity differs")
	}
	if len(prefix) != len(data) {
		if n, e := file.WriteAt(data[len(prefix):], int64(len(prefix))); e != nil || n != len(data)-len(prefix) {
			return errors.Join(e, io.ErrShortWrite)
		}
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
