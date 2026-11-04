//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

func readRemovalQuarantineAt(dir *os.File, owner uint32, fence removalFence, plan removalPlan) ([]byte, syscall.Stat_t, removalJournal, error) {
	var zero syscall.Stat_t
	info, e := dir.Stat()
	if e != nil {
		return nil, zero, removalJournal{}, e
	}
	st := info.Sys().(*syscall.Stat_t)
	seed, e := removalQuarantineSeed(fence, plan, uint64(st.Dev), st.Ino)
	if e != nil {
		return nil, zero, removalJournal{}, e
	}
	var named unix.Stat_t
	if e = unix.Fstatat(int(dir.Fd()), removalQuarantineJournalName, &named, unix.AT_SYMLINK_NOFOLLOW); errors.Is(e, unix.ENOENT) {
		journal, e := decodeRemovalJournal(nil, seed, 1)
		return nil, zero, journal, e
	} else if e != nil {
		return nil, zero, removalJournal{}, e
	}
	if owner != 0 {
		return nil, zero, removalJournal{}, errors.New("quarantine requires root authority")
	}
	raw, actual, e := readAt(dir, removalQuarantineJournalName, maxRemovalQuarantineBytes)
	if e != nil {
		return nil, zero, removalJournal{}, e
	}
	if actual.Mode&07777 != 0600 {
		return nil, zero, removalJournal{}, errors.New("quarantine journal mode differs")
	}
	if e = removalFileStillAt(dir, removalQuarantineJournalName, actual); e != nil {
		return nil, zero, removalJournal{}, e
	}
	journal, e := decodeRemovalJournal(raw, seed, 1)
	return raw, actual, journal, e
}

func (r *removalIntentStore) persistQuarantine(expected []byte, appendRecord bool) (result error) {
	if e := r.verifyIntentMetadata(); e != nil {
		return e
	}
	raw, st, journal, e := readRemovalQuarantineAt(r.store.current, 0, r.fence, r.plan)
	if e != nil || !bytes.Equal(raw, expected) {
		return errors.Join(e, errors.New("quarantine journal changed before persistence"))
	}
	var file *os.File
	if st.Ino == 0 {
		if !appendRecord {
			return errors.New("cannot acknowledge absent quarantine journal")
		}
		file, e = darwintrust.CreateRegularAt(r.store.current, removalQuarantineJournalName, 0)
		if e == nil {
			e = file.Chown(0, 0)
		}
	} else {
		var fd int
		fd, e = unix.Openat(int(r.store.current.Fd()), removalQuarantineJournalName, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e == nil {
			file = os.NewFile(uintptr(fd), "protected-quarantine-journal")
			e = deploymentObject(file, false, 0, 0600)
			if e == nil {
				var info os.FileInfo
				info, e = file.Stat()
				if e == nil && !sameState(st, *info.Sys().(*syscall.Stat_t)) {
					e = errors.New("quarantine journal vnode changed")
				}
			}
		}
	}
	if file != nil {
		defer func() { result = errors.Join(result, file.Close()) }()
	}
	if e != nil {
		return e
	}
	written := append([]byte{}, raw...)
	if appendRecord {
		if journal.completed != 0 {
			return errors.New("quarantine journal already complete")
		}
		// Only a recognized exact next-record prefix is trimmed, after the caller
		// reconciles the public/quarantined object. A partial record grants no move.
		if len(journal.tail) > 0 {
			if e = file.Truncate(int64(journal.validBytes)); e != nil {
				return e
			}
		}
		info, e := r.store.current.Stat()
		if e != nil {
			return e
		}
		state := info.Sys().(*syscall.Stat_t)
		seed, e := removalQuarantineSeed(r.fence, r.plan, uint64(state.Dev), state.Ino)
		if e != nil {
			return e
		}
		line, e := nextRemovalJournalLine(seed, journal)
		if e != nil {
			return e
		}
		n, e := file.WriteAt(line, int64(journal.validBytes))
		if e != nil || n != len(line) {
			return errors.Join(e, io.ErrShortWrite)
		}
		written = append(append([]byte{}, raw[:journal.validBytes]...), line...)
	}
	if e = r.store.phase("removal-quarantine-before-file-sync"); e != nil {
		return e
	}
	if e = fullDeploymentSync(file); e != nil {
		return e
	}
	if e = r.store.phase("removal-quarantine-before-state-sync"); e != nil {
		return e
	}
	if e = fullDeploymentSync(r.store.current); e != nil {
		return e
	}
	info, e := file.Stat()
	if e != nil {
		return e
	}
	if e = removalFileStillAt(r.store.current, removalQuarantineJournalName, *info.Sys().(*syscall.Stat_t)); e != nil {
		return e
	}
	checked, _, _, e := readRemovalQuarantineAt(r.store.current, 0, r.fence, r.plan)
	if e != nil || !bytes.Equal(written, checked) {
		return errors.Join(e, errors.New("persisted quarantine journal differs"))
	}
	return r.verifyIntentMetadata()
}

func (r *removalIntentStore) publicRemovalRoot() (removalPlanRoot, error) {
	for _, root := range r.plan.Roots {
		if root.Kind == "public" {
			return root, nil
		}
	}
	return removalPlanRoot{}, errors.New("public removal plan is absent")
}
func removalNameAbsent(parent *os.File, name string) error {
	var st unix.Stat_t
	if e := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
		return errors.Join(e, errors.New("public removal name is not absent"))
	}
	return nil
}
func (r *removalIntentStore) openPublicRemovalParent(resolve removalParentResolver) (removalTargetParent, error) {
	parent, e := resolve("public")
	if e != nil {
		return removalTargetParent{}, errors.Join(e, parent.Close())
	}
	fail := func(e error) (removalTargetParent, error) {
		return removalTargetParent{}, errors.Join(e, parent.Close())
	}
	if parent.file == nil || parent.check == nil {
		return fail(errors.New("incomplete public removal parent"))
	}
	if e = parent.check(); e != nil {
		return fail(e)
	}
	expected, e := r.publicRemovalRoot()
	if e != nil {
		return fail(e)
	}
	info, e := parent.file.Stat()
	if e != nil {
		return fail(e)
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != expected.ParentDevice || st.Ino != expected.ParentInode || uint64(st.Dev) != r.plan.Authority.RootDevice {
		return fail(errors.New("public removal parent identity or filesystem changed"))
	}
	return parent, nil
}
func (r *removalIntentStore) quarantineTarget() (removalPlanRoot, removalParentResolver, error) {
	expected, e := r.publicRemovalRoot()
	if e != nil {
		return expected, nil, e
	}
	info, e := r.store.current.Stat()
	if e != nil {
		return expected, nil, e
	}
	st := info.Sys().(*syscall.Stat_t)
	expected.Key = removalQuarantineName
	expected.ParentDevice, expected.ParentInode = uint64(st.Dev), st.Ino
	resolve := func(kind string) (removalTargetParent, error) {
		if kind != "public" {
			return removalTargetParent{}, errors.New("unexpected quarantine target role")
		}
		return removalTargetParent{r.store.current, false, func() error {
			return errors.Join(r.store.checkRoot(), sameDeploymentEntry(r.store.root, "state", r.store.current, 0))
		}}, nil
	}
	return expected, resolve, nil
}

// Check only the moved entry itself before opening/traversing it. An unknown
// file, symlink or directory must never become a tree verification/deletion root.
func (r *removalIntentStore) quarantineRootMatches() (bool, error) {
	expected, e := r.publicRemovalRoot()
	if e != nil {
		return false, e
	}
	var st unix.Stat_t
	if e = unix.Fstatat(int(r.store.current.Fd()), removalQuarantineName, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return false, e
	}
	want := expected.Objects[0]
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == 0755 && st.Uid == 0 && st.Gid == 0 && uint64(st.Dev) == want.Device && st.Ino == want.Inode, nil
}
func (r *removalIntentStore) verifyQuarantineTree(ctx context.Context) error {
	matches, e := r.quarantineRootMatches()
	if e != nil || !matches {
		return errors.Join(e, errors.New("moved public entry does not match recorded root"))
	}
	expected, resolve, e := r.quarantineTarget()
	if e != nil {
		return e
	}
	// The raw verifier has no public-location remapping. The complete saved
	// object list is compared at the protected destination after root lstat.
	return r.verifyTargetAtNamespace(ctx, expected, r.plan, resolve)
}
func (r *removalIntentStore) checkPublicAbsent(resolve removalParentResolver) (result error) {
	parent, e := r.openPublicRemovalParent(resolve)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, parent.Close()) }()
	expected, e := r.publicRemovalRoot()
	if e != nil {
		return e
	}
	return errors.Join(removalNameAbsent(parent.file, expected.Key), parent.check())
}

// No deletion occurs here. The public app is atomically moved to a fixed
// protected name only after a durable, fence-bound intent. Unknown moved
// entries are restored without replacement when possible, otherwise retained.
func (r *removalIntentStore) quarantinePublicApp(ctx context.Context) error {
	return r.quarantinePublicAppUsing(ctx, r.fixedTargetParent)
}
func (r *removalIntentStore) quarantinePublicAppUsing(ctx context.Context, resolve removalParentResolver) (result error) {
	if r == nil || r.store == nil || r.store.owner != 0 || r.store.current == nil || r.store.runtimeLock == nil || resolve == nil {
		return errors.New("public quarantine requires an open leased root intent")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if bounded.Err() != nil {
		return errors.New("public quarantine deadline exceeded")
	}
	if e := r.syncRemovalBarrier(); e != nil {
		return e
	}
	raw, _, journal, e := readRemovalQuarantineAt(r.store.current, 0, r.fence, r.plan)
	if e != nil {
		return e
	}
	if journal.completed == 1 {
		if e = r.requirePublicQuarantine(bounded, resolve); e != nil {
			return e
		}
		return nil
	}
	actions, e := removalProtectedActions(r.plan)
	if e != nil {
		return e
	}
	_, _, progress, e := readRemovalJournalAt(r.store.current, 0, removalJournalSeed(r.fence), len(actions))
	if e != nil {
		return e
	}
	if progress.entries != 0 || len(progress.tail) != 0 {
		return errors.New("public quarantine must precede protected payload removal")
	}
	parent, e := r.openPublicRemovalParent(resolve)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, parent.Close()) }()
	expected, e := r.publicRemovalRoot()
	if e != nil {
		return e
	}
	var moved unix.Stat_t
	e = unix.Fstatat(int(r.store.current.Fd()), removalQuarantineName, &moved, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		if _, e = r.verifyIntactTargetsUsing(bounded, resolve); e != nil {
			return e
		}
		if e = r.persistQuarantine(raw, !journal.pending); e != nil {
			return e
		}
		if e = r.store.phase("removal-quarantine-intent-durable"); e != nil {
			return e
		}
		// Recheck complete trees, metadata and parent immediately before moving.
		if _, e = r.verifyIntactTargetsUsing(bounded, resolve); e != nil {
			return e
		}
		if e = parent.check(); e != nil {
			return e
		}
		if e = r.store.phase("removal-quarantine-before-rename"); e != nil {
			return e
		}
		if bounded.Err() != nil {
			return errors.New("public quarantine deadline exceeded")
		}
		if e = darwintrust.RenameEntryNoReplace(parent.file, expected.Key, r.store.current, removalQuarantineName); e != nil {
			return e
		}
		if e = r.store.phase("removal-quarantine-renamed"); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if !journal.pending {
		return errors.New("unrecorded quarantined entry; preserve and inspect")
	}
	// Root-only lstat precedes any payload traversal. Restore a raced entry only
	// to an absent public name. A conflicting public object is never replaced.
	matches, e := r.quarantineRootMatches()
	if e != nil {
		return e
	}
	if !matches {
		if bounded.Err() != nil {
			return errors.New("unknown moved entry preserved after deadline")
		}
		if e = r.verifyIntentMetadata(); e != nil {
			return e
		}
		if e = parent.check(); e != nil {
			return e
		}
		if e = removalNameAbsent(parent.file, expected.Key); e != nil {
			return errors.Join(e, errors.New("unknown quarantined entry and public conflict preserved"))
		}
		if e = darwintrust.RenameEntryNoReplace(r.store.current, removalQuarantineName, parent.file, expected.Key); e != nil {
			return errors.Join(e, errors.New("unknown quarantined entry preserved"))
		}
		return errors.Join(fullDeploymentSync(r.store.current), fullDeploymentSync(parent.file), errors.New("raced public entry restored without replacement; removal refused"))
	}
	if e = r.checkPublicAbsent(resolve); e != nil {
		return e
	}
	if e = r.verifyQuarantineTree(bounded); e != nil {
		return e
	}
	for _, root := range r.plan.Roots {
		if root.Kind != "public" {
			if e = r.verifyIntactTarget(bounded, root, resolve); e != nil {
				return e
			}
		}
	}
	if e = r.verifyIntentMetadata(); e != nil {
		return e
	}
	if bounded.Err() != nil {
		return errors.New("public quarantine deadline exceeded")
	}
	if e = errors.Join(fullDeploymentSync(parent.file), fullDeploymentSync(r.store.current)); e != nil {
		return e
	}
	if e = r.store.phase("removal-quarantine-parents-durable"); e != nil {
		return e
	}
	if e = r.checkPublicAbsent(resolve); e != nil {
		return e
	}
	if e = r.verifyQuarantineTree(bounded); e != nil {
		return e
	}
	raw, _, journal, e = readRemovalQuarantineAt(r.store.current, 0, r.fence, r.plan)
	if e != nil || !journal.pending {
		return errors.Join(e, errors.New("quarantine intent disappeared before completion"))
	}
	if e = r.persistQuarantine(raw, true); e != nil {
		return e
	}
	if e = r.store.phase("removal-quarantine-done-durable"); e != nil {
		return e
	}
	return r.requirePublicQuarantine(bounded, resolve)
}

func (r *removalIntentStore) requirePublicQuarantine(ctx context.Context, resolve removalParentResolver) error {
	if ctx.Err() != nil {
		return errors.New("public quarantine deadline exceeded")
	}
	if e := r.verifyIntentMetadata(); e != nil {
		return e
	}
	raw, _, journal, e := readRemovalQuarantineAt(r.store.current, 0, r.fence, r.plan)
	if e != nil || journal.completed != 1 {
		return errors.Join(e, errors.New("durable public quarantine is required before payload removal"))
	}
	if e = r.checkPublicAbsent(resolve); e != nil {
		return e
	}
	if e = r.verifyRemainingQuarantinedApp(ctx, resolve); e != nil {
		return e
	}
	// A readable done record may have survived failed synchronization.
	if e = r.persistQuarantine(raw, false); e != nil {
		return e
	}
	if e = r.checkPublicAbsent(resolve); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return errors.New("public quarantine deadline exceeded")
	}
	return nil
}
