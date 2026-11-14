//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// Only a fully bound private removal intent can request retirement. The
// production caller will pass the fixed system tool and target resolver.
func (r *removalIntentStore) retireNextReceiptUsing(ctx context.Context, resolve removalParentResolver, forget func(context.Context, string) error) (removalProgress, error) {
	if r == nil || r.store == nil || r.store.owner != 0 || r.store.current == nil || r.store.runtimeLock == nil || resolve == nil || forget == nil {
		return removalProgress{}, errors.New("receipt retirement requires an open root intent")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := r.requirePublicQuarantine(bounded, resolve); e != nil {
		return removalProgress{}, e
	}
	return r.removeNextRemovalObjectUsing(bounded, resolve, removalReceiptScope, forget)
}

func (r *removalIntentStore) retireReceipt(ctx context.Context, resolve removalParentResolver, bom removalFileAction, actions []removalFileAction, raw []byte, journal removalJournal, forget func(context.Context, string) error) (result removalProgress, failure error) {
	zero := removalProgress{}
	id, plist, e := receiptActionPair(r.plan, bom)
	if e != nil {
		return zero, e
	}
	dir, e := r.openRemovalObjectParent(bom, resolve)
	if e != nil {
		return zero, e
	}
	defer func() {
		failure = errors.Join(failure, dir.Close())
		if failure != nil {
			result = zero
		}
	}()
	present, e := r.verifiedReceiptFiles(dir, bom, plist, journal.pending)
	if e != nil {
		return zero, e
	}
	raw, journal, e = r.persistRemovalJournal(raw, !journal.pending)
	if e != nil {
		return zero, e
	}
	if e = r.store.phase("removal-receipt-intent-durable"); e != nil {
		return zero, e
	}
	// Inspect the whole owned namespace and the current pair immediately before
	// handing the ID to pkgutil. The filesystem API has no compare-and-forget.
	if e = r.verifyRemainingObjects(ctx, resolve, actions, journal); e != nil {
		return zero, e
	}
	if e = sameRemovalTargetParent(dir, func() (*os.File, error) { return r.openRemovalObjectParent(bom, resolve) }); e != nil {
		return zero, e
	}
	checked, e := r.verifiedReceiptFiles(dir, bom, plist, true)
	if e != nil || checked != present {
		return zero, errors.Join(e, errors.New("receipt pair changed before tool invocation"))
	}
	if ctx.Err() != nil {
		return zero, errors.New("receipt retirement deadline exceeded")
	}
	if present > 0 {
		if e = forget(ctx, id); e != nil {
			return zero, e
		}
		if e = r.store.phase("removal-receipt-forgotten"); e != nil {
			return zero, e
		}
	}
	for _, action := range []removalFileAction{bom, plist} {
		object := r.plan.Roots[action.root].Objects[action.object]
		var observed unix.Stat_t
		if e = unix.Fstatat(int(dir.Fd()), object.Path, &observed, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
			return zero, errors.Join(e, errors.New("retired receipt pair is not absent"))
		}
	}
	if e = fullDeploymentSync(dir); e != nil {
		return zero, e
	}
	if e = r.store.phase("removal-receipt-parent-durable"); e != nil {
		return zero, e
	}
	if e = sameRemovalTargetParent(dir, func() (*os.File, error) { return r.openRemovalObjectParent(bom, resolve) }); e != nil {
		return zero, e
	}
	_, journal, e = r.persistRemovalJournal(raw, true)
	if e != nil {
		return zero, e
	}
	if e = r.store.phase("removal-receipt-done-durable"); e != nil {
		return zero, e
	}
	if e = r.verifyRemainingObjects(ctx, resolve, actions, journal); e != nil {
		return zero, e
	}
	return removalProgress{journal.completed, len(actions)}, nil
}

func (r *removalIntentStore) verifiedReceiptFiles(dir *os.File, bom, plist removalFileAction, allowAbsent bool) (int, error) {
	present := 0
	for _, action := range []removalFileAction{bom, plist} {
		object := r.plan.Roots[action.root].Objects[action.object]
		data, st, e := readAt(dir, object.Path, 4<<20)
		if darwintrust.IsReadAbsent(e) && allowAbsent {
			continue
		}
		if e != nil || !removalFileMatches(object, data, st) {
			return 0, errors.Join(e, errors.New("receipt file changed before retirement"))
		}
		present++
	}
	return present, nil
}

func (r *removalIntentStore) observePendingReceiptAbsence(resolve removalParentResolver, bom, plist removalFileAction, absent map[removalFileAction]bool) (result error) {
	dir, e := r.openRemovalObjectParent(bom, resolve)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, dir.Close()) }()
	for _, action := range []removalFileAction{bom, plist} {
		object := r.plan.Roots[action.root].Objects[action.object]
		var st unix.Stat_t
		e = unix.Fstatat(int(dir.Fd()), object.Path, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(e, unix.ENOENT) {
			absent[action] = true
		} else if e != nil {
			return e
		}
	}
	return nil
}
