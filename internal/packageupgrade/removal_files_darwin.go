//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

type removalProgress struct{ completed, total int }
type removalFileProgress = removalProgress

type removalObjectScope uint8

const (
	removalFileScope removalObjectScope = iota
	removalProtectedScope
	removalPayloadScope
	removalRegistrationScope
	removalReceiptScope
)

// Private, one-file transaction. There is no CLI/package entry point.
// Directory removal, public-app quarantine, receipts and finalization are
// deliberately outside this primitive's action set.
func (r *removalIntentStore) removeNextProtectedFile(ctx context.Context) (removalFileProgress, error) {
	return r.removeNextQuarantinedProtectedObjectUsing(ctx, r.fixedTargetParent, true)
}
func (r *removalIntentStore) removeNextProtectedFileUsing(ctx context.Context, resolve removalParentResolver) (removalFileProgress, error) {
	return r.removeNextProtectedObjectUsing(ctx, resolve, true)
}
func (r *removalIntentStore) removeNextProtectedObject(ctx context.Context) (removalProgress, error) {
	return r.removeNextQuarantinedProtectedObjectUsing(ctx, r.fixedTargetParent, false)
}

// Fixed production-facing primitives require completed quarantine first.
// The lower-level resolver method remains private for isolated owned fixtures.
func (r *removalIntentStore) removeNextQuarantinedProtectedObjectUsing(ctx context.Context, resolve removalParentResolver, filesOnly bool) (removalProgress, error) {
	if r == nil || r.store == nil || r.store.owner != 0 || r.store.current == nil || r.store.runtimeLock == nil || resolve == nil {
		return removalProgress{}, errors.New("protected removal requires an open root intent")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := r.requirePublicQuarantine(bounded, resolve); e != nil {
		return removalProgress{}, e
	}
	return r.removeNextProtectedObjectUsing(bounded, resolve, filesOnly)
}

// Each call mutates at most one recorded object. Directory actions use only
// nonrecursive rmdir after every recorded child has durable completion.
func (r *removalIntentStore) removeNextProtectedObjectUsing(ctx context.Context, resolve removalParentResolver, filesOnly bool) (removalProgress, error) {
	scope := removalProtectedScope
	if filesOnly {
		scope = removalFileScope
	}
	return r.removeNextRemovalObjectUsing(ctx, resolve, scope, nil)
}
func (r *removalIntentStore) removeNextRemovalObjectUsing(ctx context.Context, resolve removalParentResolver, scope removalObjectScope, forget func(context.Context, string) error) (result removalProgress, failure error) {
	zero := removalProgress{}
	if r == nil || r.store == nil || r.store.owner != 0 || r.store.current == nil || r.store.runtimeLock == nil || resolve == nil {
		return zero, errors.New("protected object removal requires an open leased root intent")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if bounded.Err() != nil {
		return zero, errors.New("removal deadline exceeded")
	}
	if e := r.syncRemovalBarrier(); e != nil {
		return zero, e
	}
	actions, e := removalAllActions(r.plan)
	if e != nil {
		return zero, e
	}
	var prefix []removalFileAction
	switch scope {
	case removalFileScope:
		prefix, e = removalFileActions(r.plan)
	case removalProtectedScope:
		prefix, e = removalProtectedActions(r.plan)
	case removalPayloadScope, removalRegistrationScope:
		prefix, e = removalPayloadActions(r.plan)
	case removalReceiptScope:
		prefix, e = removalRegistrationActions(r.plan)
	default:
		return zero, errors.New("invalid removal action scope")
	}
	if e != nil {
		return zero, e
	}
	limit := len(prefix)
	raw, _, journal, e := readRemovalJournalAt(r.store.current, 0, removalJournalSeed(r.fence), len(actions))
	if e != nil {
		return zero, e
	}
	if scope == removalRegistrationScope {
		if journal.completed < limit {
			return zero, errors.New("registration removal requires completed payload removal")
		}
		registrations, e := removalRegistrationActions(r.plan)
		if e != nil {
			return zero, e
		}
		limit = len(registrations)
	}
	if scope == removalReceiptScope {
		if journal.completed < limit || forget == nil {
			return zero, errors.New("receipt retirement requires completed registration removal and a fixed tool")
		}
		limit = len(actions)
	}
	if scope == removalReceiptScope && journal.completed == len(actions) {
		if _, e = r.verifyCompletedRemoval(bounded, resolve); e != nil {
			return zero, e
		}
		return removalProgress{len(actions), len(actions)}, nil
	}
	if e = r.verifyRemainingObjects(bounded, resolve, actions, journal); e != nil {
		return zero, e
	}
	again, _, _, e := readRemovalJournalAt(r.store.current, 0, removalJournalSeed(r.fence), len(actions))
	if e != nil || !bytes.Equal(raw, again) {
		return zero, errors.Join(e, errors.New("removal progress changed during reconciliation"))
	}
	if journal.completed >= limit {
		if e = r.syncObservedRemovalJournal(raw); e != nil {
			return zero, e
		}
		if bounded.Err() != nil {
			return zero, errors.New("protected object completion deadline exceeded")
		}
		return removalProgress{limit, limit}, nil
	}
	if bounded.Err() != nil {
		return zero, errors.New("protected object removal deadline exceeded")
	}
	action := actions[journal.completed]
	if scope == removalReceiptScope {
		return r.retireReceipt(bounded, resolve, action, actions, raw, journal, forget)
	}
	object := r.plan.Roots[action.root].Objects[action.object]
	phase := "removal-file"
	if object.Kind == "directory" {
		phase = "removal-directory"
	}
	if r.plan.Roots[action.root].Kind == "registrations" {
		phase = "removal-registration"
	}
	if r.plan.Roots[action.root].Kind == "public" {
		phase = "removal-app-file"
		if object.Kind == "directory" {
			phase = "removal-app-directory"
		}
	}
	raw, journal, e = r.persistRemovalJournal(raw, !journal.pending)
	if e != nil {
		return zero, e
	}
	if e = r.store.phase(phase + "-intent-durable"); e != nil {
		return zero, e
	}
	dir, e := r.openRemovalObjectParent(action, resolve)
	if e != nil {
		return zero, e
	}
	defer func() {
		failure = errors.Join(failure, dir.Close())
		if failure != nil {
			result = zero
		}
	}()
	name := removalObjectName(r.plan.Roots[action.root], object)
	var data []byte
	var st syscall.Stat_t
	var target *os.File
	if object.Kind == "file" {
		data, st, e = readAt(dir, name, 64<<20)
	} else {
		target, e = deploymentDirectory(dir, name, 0, false)
		if target != nil {
			defer func() {
				failure = errors.Join(failure, target.Close())
				if failure != nil {
					result = zero
				}
			}()
		}
		if e == nil {
			var info os.FileInfo
			info, e = target.Stat()
			if e == nil {
				st = *info.Sys().(*syscall.Stat_t)
			}
			if e == nil {
				e = verifyEmptyRemovalDirectory(dir, name, target, object)
			}
		}
	}
	if darwintrust.IsReadAbsent(e) {
		// Only the one canonical pending intent admits absence. A reopened
		// protected parent must still match the frozen plan.
		if !journal.pending {
			return zero, errors.New("unrecorded removal object absence")
		}
	} else if e != nil {
		return zero, e
	} else {
		if object.Kind == "file" && !removalFileMatches(object, data, st) {
			return zero, errors.New("removal file changed before unlink")
		}
		if object.Kind == "file" {
			if e = removalFileStillAt(dir, name, st); e != nil {
				return zero, e
			}
		}
	}
	if e = r.verifyIntentMetadata(); e != nil {
		return zero, e
	}
	if e = sameRemovalTargetParent(dir, func() (*os.File, error) { return r.openRemovalObjectParent(action, resolve) }); e != nil {
		return zero, e
	}
	if bounded.Err() != nil {
		return zero, errors.New("protected object removal deadline exceeded")
	}
	if st.Ino != 0 {
		if object.Kind == "file" {
			if e = removalFileStillAt(dir, name, st); e != nil {
				return zero, e
			}
		}
		flags := 0
		if object.Kind == "directory" {
			if e = verifyEmptyRemovalDirectory(dir, name, target, object); e != nil {
				return zero, e
			}
			flags = unix.AT_REMOVEDIR
		}
		if e = unix.Unlinkat(int(dir.Fd()), name, flags); e != nil {
			return zero, e
		}
		if e = r.store.phase(phase + "-unlinked"); e != nil {
			return zero, e
		}
	}
	var after unix.Stat_t
	if e = unix.Fstatat(int(dir.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
		return zero, errors.New("removed object name is not absent")
	}
	if e = fullDeploymentSync(dir); e != nil {
		return zero, e
	}
	if e = r.store.phase(phase + "-parent-durable"); e != nil {
		return zero, e
	}
	_, journal, e = r.persistRemovalJournal(raw, true)
	if e != nil {
		return zero, e
	}
	if e = r.store.phase(phase + "-done-durable"); e != nil {
		return zero, e
	}
	if e = r.verifyRemainingObjects(bounded, resolve, actions, journal); e != nil {
		return zero, e
	}
	return removalProgress{journal.completed, limit}, nil
}
func removalFileMatches(want removalPlanObject, data []byte, st syscall.Stat_t) bool {
	mode := uint16(0644)
	if want.Mode == "0755" {
		mode = 0755
	}
	return want.Kind == "file" && st.Mode&07777 == mode && uint64(st.Dev) == want.Device && st.Ino == want.Inode && int64(len(data)) == want.Bytes && removalDigest(data) == want.SHA256 && st.Mtimespec.Sec*1e9+st.Mtimespec.Nsec == want.MtimeNs && st.Ctimespec.Sec*1e9+st.Ctimespec.Nsec == want.CtimeNs
}
func (r *removalIntentStore) openRemovalObjectParent(action removalFileAction, resolve removalParentResolver) (result *os.File, failure error) {
	if action.root < 0 || action.root >= len(r.plan.Roots) {
		return nil, errors.New("invalid protected removal action")
	}
	root := r.plan.Roots[action.root]
	if action.object < 0 || action.object >= len(root.Objects) {
		return nil, errors.New("ineligible protected removal object")
	}
	object := root.Objects[action.object]
	switch root.Kind {
	case "core", "incoming", "public":
		if object.Kind != "file" && object.Kind != "directory" {
			return nil, errors.New("ineligible protected removal object")
		}
	case "registrations", "receipts":
		if object.Kind != "file" || path.Base(object.Path) != object.Path {
			return nil, errors.New("ineligible removal metadata object")
		}
	default:
		return nil, errors.New("ineligible protected removal object")
	}
	if root.Kind == "public" {
		_, _, quarantine, e := readRemovalQuarantineAt(r.store.current, 0, r.fence, r.plan)
		if e != nil || quarantine.completed != 1 {
			return nil, errors.Join(e, errors.New("public object requires completed quarantine"))
		}
		root, resolve, e = r.quarantineTarget()
		if e != nil {
			return nil, e
		}
	}
	parent, e := resolve(root.Kind)
	if e != nil {
		return nil, errors.Join(e, parent.Close())
	}
	defer func() {
		failure = errors.Join(failure, parent.Close())
		if failure != nil && result != nil {
			failure = errors.Join(failure, result.Close())
			result = nil
		}
	}()
	if parent.file == nil || parent.check == nil {
		return nil, errors.New("incomplete protected removal parent")
	}
	if e = parent.check(); e != nil {
		return nil, e
	}
	if e = deploymentObject(parent.file, true, 0, 0755); e != nil {
		return nil, e
	}
	info, e := parent.file.Stat()
	if e != nil {
		return nil, e
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != root.ParentDevice || st.Ino != root.ParentInode {
		return nil, errors.New("protected removal parent changed")
	}
	if action.object == 0 {
		fd, e := unix.Openat(int(parent.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		held := os.NewFile(uintptr(fd), "protected-removal-root-parent")
		if e = deploymentObject(held, true, 0, 0755); e == nil {
			e = parent.check()
		}
		if e != nil {
			return nil, errors.Join(e, held.Close())
		}
		return held, nil
	}
	current, e := deploymentDirectory(parent.file, root.Key, 0, false)
	if e != nil {
		return nil, e
	}
	check := func(file *os.File, want removalPlanObject) error {
		info, e := file.Stat()
		if e != nil {
			return e
		}
		st := info.Sys().(*syscall.Stat_t)
		if uint64(st.Dev) != want.Device || st.Ino != want.Inode {
			return errors.New("protected removal directory changed")
		}
		return nil
	}
	if e = check(current, root.Objects[0]); e != nil {
		return nil, errors.Join(e, current.Close())
	}
	directory := path.Dir(root.Objects[action.object].Path)
	if directory != "." {
		prefix := ""
		for _, part := range strings.Split(directory, "/") {
			if prefix != "" {
				prefix += "/"
			}
			prefix += part
			var want removalPlanObject
			for _, object := range root.Objects {
				if object.Path == prefix && object.Kind == "directory" {
					want = object
					break
				}
			}
			if want.Inode == 0 {
				return nil, errors.Join(errors.New("unplanned removal ancestor"), current.Close())
			}
			next, e := deploymentDirectory(current, part, 0, false)
			closeErr := current.Close()
			if e != nil || closeErr != nil {
				if next != nil {
					closeErr = errors.Join(closeErr, next.Close())
				}
				return nil, errors.Join(e, closeErr)
			}
			current = next
			if e = check(current, want); e != nil {
				return nil, errors.Join(e, current.Close())
			}
		}
	}
	if e = parent.check(); e != nil {
		return nil, errors.Join(e, current.Close())
	}
	return current, nil
}
func (r *removalIntentStore) removalAbsences(resolve removalParentResolver, actions []removalFileAction, journal removalJournal) (map[removalFileAction]bool, error) {
	absent := map[removalFileAction]bool{}
	for i := 0; i < journal.completed; i++ {
		action := actions[i]
		absent[action] = true
		if r.plan.Roots[action.root].Kind == "receipts" {
			_, plist, e := receiptActionPair(r.plan, action)
			if e != nil {
				return nil, e
			}
			absent[plist] = true
		}
	}
	if journal.pending {
		action := actions[journal.completed]
		if r.plan.Roots[action.root].Kind == "receipts" {
			_, plist, e := receiptActionPair(r.plan, action)
			if e != nil {
				return nil, e
			}
			if e = r.observePendingReceiptAbsence(resolve, action, plist, absent); e != nil {
				return nil, e
			}
			return absent, nil
		}
		dir, e := r.openRemovalObjectParent(action, resolve)
		if e != nil {
			return nil, e
		}
		var st unix.Stat_t
		e = unix.Fstatat(int(dir.Fd()), removalObjectName(r.plan.Roots[action.root], r.plan.Roots[action.root].Objects[action.object]), &st, unix.AT_SYMLINK_NOFOLLOW)
		closeErr := dir.Close()
		if errors.Is(e, unix.ENOENT) {
			absent[action] = true
			e = nil
		}
		if e = errors.Join(e, closeErr); e != nil {
			return nil, e
		}
	}
	return absent, nil
}
func (r *removalIntentStore) verifyRemainingObjects(ctx context.Context, resolve removalParentResolver, actions []removalFileAction, journal removalJournal) error {
	absent, e := r.removalAbsences(resolve, actions, journal)
	if e != nil {
		return e
	}

	namespace := r.plan
	namespace.Roots = make([]removalPlanRoot, 0, len(r.plan.Roots))
	for i, root := range r.plan.Roots {
		if !absent[removalFileAction{i, 0}] {
			namespace.Roots = append(namespace.Roots, root)
		}
	}
	for pass := 0; pass < 2; pass++ {
		if ctx.Err() != nil {
			return errors.New("removal reconciliation deadline exceeded")
		}
		if e := r.verifyIntentMetadata(); e != nil {
			return e
		}
		for i, root := range r.plan.Roots {
			expected := root
			expected.Objects = make([]removalPlanObject, 0, len(root.Objects))
			for j, object := range root.Objects {
				if !absent[removalFileAction{i, j}] {
					expected.Objects = append(expected.Objects, object)
				}
			}
			if absent[removalFileAction{i, 0}] && len(expected.Objects) != 0 {
				return errors.New("removed root still has uncompleted child actions")
			}
			if e := r.verifyTargetWithNamespace(ctx, expected, namespace, resolve); e != nil {
				return e
			}
		}
		if e := r.verifyIntentMetadata(); e != nil {
			return e
		}
	}
	if ctx.Err() != nil {
		return errors.New("removal reconciliation deadline exceeded")
	}
	return nil
}
