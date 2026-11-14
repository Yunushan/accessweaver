//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"context"
	"errors"
	"time"
)

// No public CLI/package phase reaches this primitive. It removes at most one
// recorded object inside state/public-app, after the protected prefix finishes.
// Every regular-file unlink and empty-directory rmdir uses the same durable
// journal, exact saved vnode checks and full remaining-target reconciliation.
func (r *removalIntentStore) removeNextQuarantinedAppObject(ctx context.Context) (removalProgress, error) {
	return r.removeNextQuarantinedAppObjectUsing(ctx, r.fixedTargetParent)
}
func (r *removalIntentStore) removeNextQuarantinedAppObjectUsing(ctx context.Context, resolve removalParentResolver) (removalProgress, error) {
	zero := removalProgress{}
	if r == nil || r.store == nil || r.store.owner != 0 || r.store.current == nil || r.store.runtimeLock == nil || resolve == nil {
		return zero, errors.New("quarantined app removal requires an open root intent")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := r.requirePublicQuarantine(bounded, resolve); e != nil {
		return zero, e
	}
	actions, e := removalAllActions(r.plan)
	if e != nil {
		return zero, e
	}
	protected, e := removalProtectedActions(r.plan)
	if e != nil {
		return zero, e
	}
	_, _, progress, e := readRemovalJournalAt(r.store.current, 0, removalJournalSeed(r.fence), len(actions))
	if e != nil {
		return zero, e
	}
	if progress.completed < len(protected) {
		return zero, errors.New("quarantined app removal requires completed protected objects")
	}
	return r.removeNextRemovalObjectUsing(bounded, resolve, removalPayloadScope)
}

// Uses the same recorded vnode checks and durable intent as payload deletion.
func (r *removalIntentStore) removeNextRegistrationUsing(ctx context.Context, resolve removalParentResolver) (removalProgress, error) {
	if r == nil || r.store == nil || r.store.owner != 0 || r.store.current == nil || r.store.runtimeLock == nil || resolve == nil {
		return removalProgress{}, errors.New("registration removal requires an open root intent")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if e := r.requirePublicQuarantine(bounded, resolve); e != nil {
		return removalProgress{}, e
	}
	return r.removeNextRemovalObjectUsing(bounded, resolve, removalRegistrationScope)
}

func (r *removalIntentStore) verifyRemainingQuarantinedApp(ctx context.Context, resolve removalParentResolver) error {
	actions, e := removalAllActions(r.plan)
	if e != nil {
		return e
	}
	_, _, journal, e := readRemovalJournalAt(r.store.current, 0, removalJournalSeed(r.fence), len(actions))
	if e != nil {
		return e
	}
	absent, e := r.removalAbsences(resolve, actions, journal)
	if e != nil {
		return e
	}
	for i, root := range r.plan.Roots {
		if root.Kind != "public" {
			continue
		}
		expected := root
		expected.Objects = nil
		for j, object := range root.Objects {
			if !absent[removalFileAction{i, j}] {
				expected.Objects = append(expected.Objects, object)
			}
		}
		if absent[removalFileAction{i, 0}] && len(expected.Objects) != 0 {
			return errors.New("removed quarantined root has unfinished children")
		}
		return r.verifyTargetWithNamespace(ctx, expected, r.plan, resolve)
	}
	return errors.New("quarantined public target is absent from plan")
}
