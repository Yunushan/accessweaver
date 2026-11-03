//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"errors"
	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
	"os"
)

const deploymentIncoming = "AccessWeaver Incoming"

func legacyDeploymentAbsent() error {
	apps, e := applications()
	if e != nil {
		return e
	}
	defer apps.Close()
	receipts, e := darwintrust.OpenRootDirectory("/private/var/db/receipts")
	if e != nil {
		return e
	}
	defer receipts.Close()
	for _, object := range []struct {
		parent *os.File
		name   string
	}{{apps, "AccessWeaver.app"}, {receipts, BundleID + ".plist"}, {receipts, BundleID + ".bom"}} {
		var st unix.Stat_t
		e = unix.Fstatat(int(object.parent.Fd()), object.name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if e == nil {
			return errors.New("legacy app or receipt exists; explicit migration is required")
		}
		if !errors.Is(e, unix.ENOENT) {
			return e
		}
	}
	return nil
}
func openDeploymentIncoming(identity deploymentIdentity) (*os.File, error) {
	parent, e := darwintrust.OpenRootDirectory(deploymentParent)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	incoming, e := deploymentDirectory(parent, deploymentIncoming, 0, false)
	if e != nil {
		return nil, e
	}
	defer incoming.Close()
	stage, e := deploymentDirectory(incoming, identity.ManifestSHA256, 0, false)
	if e != nil {
		return nil, e
	}
	// The exact legacy or schema2 container stays held through the copy.
	// Both detached metadata files are authenticated by the compiled seal.
	return stage, nil
}
func (s *deploymentStore) matchingPending(identity deploymentIdentity) (deploymentPending, bool, error) {
	var found deploymentPending
	count := 0
	for _, pending := range s.state.Pending {
		if pending.Slot.Identity == identity {
			found = pending
			count++
		}
	}
	if count > 1 {
		return found, false, errors.New("multiple matching prepared deployments; preserve and inspect")
	}
	return found, count == 1, nil
}
func (s *deploymentStore) reconcileDeployment(op string, identity deploymentIdentity, openSource func() (*os.File, error)) (deploymentSlot, bool, string, error) {
	pending, found, e := s.matchingPending(identity)
	if e != nil {
		return deploymentSlot{}, false, "refused", e
	}
	switch op {
	case "prepare-deployment":
		if found {
			if pending.BaseGeneration != s.state.Generation {
				return pending.Slot, false, "fenced", errors.New("prior preparation is fenced; abandon explicitly before retry")
			}
			dir, e := s.openSlot(pending.Slot)
			if e != nil {
				return pending.Slot, false, "refused", e
			}
			e = dir.Close()
			return pending.Slot, false, "prepared", e
		}
		before := append([]byte{}, s.encoded...)
		slot, e := s.prepare(identity)
		return slot, !bytes.Equal(before, s.encoded), "prepared", e
	case "activate-deployment":
		if !found {
			if s.state.Active.Identity != identity {
				return deploymentSlot{}, false, "refused", errors.New("no matching prepared or active deployment")
			}
			slot := s.state.Active
			_, e := s.activatePrepared(slot)
			return slot, false, "active", e
		}
		if pending.BaseGeneration != s.state.Generation {
			return pending.Slot, false, "fenced", errors.New("prepared deployment is fenced by a newer operation")
		}
		dir, e := s.openSlot(pending.Slot)
		if e != nil {
			return pending.Slot, false, "refused", e
		}
		entries, readErr := deploymentEntries(dir, 0, 3)
		closeErr := dir.Close()
		if e = errors.Join(readErr, closeErr); e != nil {
			return pending.Slot, false, "refused", e
		}
		if len(entries) != 0 {
			published, e := s.activatePrepared(pending.Slot)
			return pending.Slot, published, "active", e
		}
		app, e := openSource()
		if e != nil {
			return pending.Slot, false, "refused", e
		}
		published, copyErr := s.copyIncomingAndActivate(pending.Slot, app)
		return pending.Slot, published, "active", errors.Join(copyErr, app.Close())
	case "deactivate-deployment":
		// An older helper cannot deactivate a newer or differently sealed app.
		if s.state.Active.Identity != identity {
			return deploymentSlot{}, false, "refused", errors.New("active deployment differs from compiled helper seal")
		}
		slot := s.state.Active
		if e := s.verifySlot(slot); e != nil {
			return slot, false, "refused", e
		}
		published, e := s.deactivate()
		return slot, published, "inactive", e
	case "abandon-deployment":
		if !found {
			return deploymentSlot{}, false, "refused", errors.New("no matching preparation to abandon")
		}
		// Abandon the record, not its files. No guessed recursive deletion.
		published, e := s.abandon(pending.Slot.ID)
		return pending.Slot, published, "abandoned", e
	}
	return deploymentSlot{}, false, "refused", errors.New("unknown deployment operation")
}

// DeploymentOperation is the narrow root-only packaging interface. Expected
// subjects are compiled in; paths and legacy-state checks are fixed. A nonzero
// exit can follow publication: callers must inspect/reconcile, never undo it.
func DeploymentOperation(op string) (result DeploymentResult, err error) {
	if !validDeploymentOperation(op) {
		return result, errors.New("unknown deployment operation")
	}
	if os.Geteuid() != 0 {
		return result, errors.New("native deployment operation requires root")
	}
	identity, e := compiledDeploymentIdentity()
	if e != nil {
		return result, e
	}
	if e = legacyDeploymentAbsent(); e != nil {
		return result, e
	}
	s, e := openDeployment(op == "prepare-deployment")
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	slot, published, state, e := s.reconcileDeployment(op, identity, func() (*os.File, error) { return openDeploymentIncoming(identity) })
	if e != nil {
		state = "refused"
	}
	result = DeploymentResult{SchemaVersion: 1, Operation: op, Generation: s.state.Generation, Version: identity.Version, ManifestSHA256: identity.ManifestSHA256, PayloadSHA256: identity.PayloadSHA256, SlotID: slot.ID, State: state, OperationRecordPublished: published}
	return result, e
}
