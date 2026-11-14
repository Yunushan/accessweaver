//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

const removalPreparationRoot = "AccessWeaver Removal Preparation"
const maxRemovalPreparations = 32

// Incomplete bundles live outside the authority history. They are bounded and
// preserved, never guessed to be old state or recursively cleaned on retry.
func (s *deploymentStore) openRemovalPreparationDirectory(resumeName string) (*os.File, error) {
	dir, e := darwintrust.CreateDirectoryAt(s.parent, removalPreparationRoot, s.owner)
	created := e == nil
	if errors.Is(e, unix.EEXIST) {
		dir, e = darwintrust.OpenDirectoryAt(s.parent, removalPreparationRoot, s.owner)
	}
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*os.File, error) { return nil, errors.Join(e, dir.Close()) }
	if created && s.owner == 0 {
		if e = dir.Chown(0, 0); e != nil {
			return fail(e)
		}
	}
	if e = deploymentObject(dir, true, s.owner, 0700); e != nil {
		return fail(e)
	}
	info, e := dir.Stat()
	if e != nil {
		return fail(e)
	}
	rootInfo, e := s.root.Stat()
	if e != nil {
		return fail(e)
	}
	if info.Sys().(*syscall.Stat_t).Dev != rootInfo.Sys().(*syscall.Stat_t).Dev {
		return fail(errors.New("removal preparation must share the authority filesystem"))
	}
	entries, e := deploymentEntries(dir, s.owner, maxRemovalPreparations)
	if e != nil {
		return fail(e)
	}
	resuming := false
	for _, entry := range entries {
		if !recordName.MatchString(entry.Name()) || !entry.IsDir() {
			return fail(errors.New("unknown removal preparation object; preserve and inspect"))
		}
		resuming = resuming || entry.Name() == resumeName
	}
	if len(entries) >= maxRemovalPreparations && !resuming {
		return fail(errors.New("removal preparation capacity exhausted; preserve and inspect"))
	}
	if created {
		if e = errors.Join(fullDeploymentSync(dir), fullDeploymentSync(s.parent)); e != nil {
			return fail(e)
		}
	}
	if e = sameDeploymentEntry(s.parent, removalPreparationRoot, dir, s.owner); e != nil {
		return fail(e)
	}
	return dir, nil
}

func (s *deploymentStore) checkRemovalPreimage(f removalFence, plan removalPlan, staging string) error {
	next, e := s.state.deactivate()
	if e != nil {
		return e
	}
	if e = f.validatePlan(next, plan); e != nil {
		return e
	}
	if f.Target != s.state.Active || f.BaseGeneration != s.state.Generation || removalDigest(s.encoded) != f.BeforeRecordSHA256 || len(s.state.Pending) != 0 {
		return errors.New("removal preparation preimage differs")
	}
	if e = verifyRemovalPlanAuthority(s, plan.Authority); e != nil {
		return e
	}
	if e = s.checkRoot(); e != nil {
		return e
	}
	if e = sameDeploymentEntry(s.root, "state", s.current, s.owner); e != nil {
		return e
	}
	actual, e := s.readRecord(s.current)
	if e != nil {
		return e
	}
	if !bytes.Equal(actual, s.encoded) {
		return errors.New("removal preparation active record changed")
	}
	before, history, e := verifyRemovalPlanHistory(s, plan, "", staging)
	if e != nil {
		return e
	}
	return verifyRemovalPlanSlots(s, plan, before, history)
}

// The complete future bundle is already under its reserved history name. No
// partial file writes occur in that namespace. Swapping binds the old state to
// the exact displaced name recorded in the immutable fence and plan.
func (s *deploymentStore) publishPreparedRemoval(f removalFence, plan removalPlan, staged *os.File) (published bool, result error) {
	if e := s.checkRemovalPreimage(f, plan, f.DisplacedRecord); e != nil {
		return false, e
	}
	observed, observedPlan, encoded, e := readRemovalBundle(staged, s.owner)
	if e != nil {
		return false, e
	}
	if observed != f || sameRemovalPlans(plan, observedPlan) != nil {
		return false, errors.New("prepared removal bundle changed")
	}
	if e = sameDeploymentEntry(s.root, f.DisplacedRecord, staged, s.owner); e != nil {
		return false, e
	}
	if e = s.checkRemovalPreimage(f, plan, f.DisplacedRecord); e != nil {
		return false, e
	}
	if e = darwintrust.RenameDirectories(s.root, f.DisplacedRecord, "state", true); e != nil {
		return false, e
	}
	old := s.current
	s.current = staged
	s.state, e = decodeDeployment(encoded)
	s.encoded = encoded
	closeErr := old.Close()
	if e != nil {
		return true, errors.Join(e, closeErr)
	}
	if e = s.phase("removal-published"); e != nil {
		return true, errors.Join(e, closeErr)
	}
	if e = errors.Join(fullDeploymentSync(s.root), closeErr); e != nil {
		return true, e
	}
	return true, s.phase("removal-parent-durable")
}

// Root/compiled seals and full saved object fingerprints are required. A name
// alone, incomplete bundle, ambiguous future records or changed preimage never
// authorize recovery. The alternate resolver factory is owned-fixture only.
func resumePreparedRemovalAt(ctx context.Context, parent *os.File, owner uint32, identity deploymentIdentity, desktopSHA string) (*removalIntentStore, bool, error) {
	return resumePreparedRemovalUsing(ctx, parent, owner, identity, desktopSHA, func(r *removalIntentStore) removalParentResolver { return r.fixedTargetParent })
}
func resumePreparedRemovalUsing(ctx context.Context, parent *os.File, owner uint32, identity deploymentIdentity, desktopSHA string, resolve func(*removalIntentStore) removalParentResolver) (result *removalIntentStore, published bool, failure error) {
	if e := identity.validate(); e != nil {
		return nil, false, errors.Join(e, parent.Close())
	}
	if !hash.MatchString(desktopSHA) || owner != 0 || resolve == nil {
		return nil, false, errors.Join(errors.New("prepared removal recovery requires root and compiled seals"), parent.Close())
	}
	s, e := openRemovalAuthorityAt(parent, owner)
	if e != nil {
		return nil, false, e
	}
	var staged *os.File
	defer func() {
		if !published {
			if staged != nil {
				failure = errors.Join(failure, staged.Close())
			}
			failure = errors.Join(failure, s.Close())
			result = nil
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, e := s.readRecord(s.current)
	if e != nil {
		return nil, false, e
	}
	s.state, e = decodeDeployment(raw)
	if e != nil {
		return nil, false, e
	}
	s.encoded = raw
	if s.state.Active.Identity != identity || len(s.state.Pending) != 0 {
		return nil, false, errors.New("active removal recovery identity differs")
	}
	entries, e := deploymentEntries(s.root, owner, maxRetainedRecords+4)
	if e != nil {
		return nil, false, e
	}
	var fence removalFence
	var plan removalPlan
	for _, entry := range entries {
		if !recordName.MatchString(entry.Name()) {
			continue
		}
		dir, e := deploymentDirectory(s.root, entry.Name(), owner, false)
		if e != nil {
			return nil, false, e
		}
		names, e := deploymentEntries(dir, owner, 3)
		if e != nil {
			return nil, false, errors.Join(e, dir.Close())
		}
		if len(names) == 1 && names[0].Name() == deploymentRecord {
			old, e := s.readRecord(dir)
			if e == nil {
				var state deploymentState
				state, e = decodeDeployment(old)
				if e == nil && state.Generation > s.state.Generation {
					e = errors.New("unrecognized future deployment record")
				}
			}
			if e = errors.Join(e, dir.Close()); e != nil {
				return nil, false, e
			}
			continue
		}
		if len(names) != 3 {
			return nil, false, errors.Join(errors.New("incomplete authority preparation; preserve and inspect"), dir.Close())
		}
		observed, captured, _, e := readRemovalBundle(dir, owner)
		if e != nil {
			return nil, false, errors.Join(e, dir.Close())
		}
		if observed.DisplacedRecord != entry.Name() || observed.Target.Identity != identity || observed.DesktopRecordSHA256 != desktopSHA {
			return nil, false, errors.Join(errors.New("prepared removal differs from compiled release"), dir.Close())
		}
		if staged != nil {
			return nil, false, errors.Join(errors.New("ambiguous prepared removal records; preserve and inspect"), dir.Close())
		}
		staged = dir
		fence, plan = observed, captured
	}
	if staged == nil {
		return nil, false, errors.New("no complete reserved removal preparation")
	}
	r := &removalIntentStore{store: s, fence: fence, plan: plan}
	resolver := resolve(r)
	if resolver == nil {
		return nil, false, errors.New("prepared removal resolver is absent")
	}
	for pass := 0; pass < 2; pass++ {
		if bounded.Err() != nil {
			return nil, false, errors.New("prepared removal recovery deadline exceeded")
		}
		if e = s.checkRemovalPreimage(fence, plan, fence.DisplacedRecord); e != nil {
			return nil, false, e
		}
		for _, root := range plan.Roots {
			if e = r.verifyIntactTarget(bounded, root, resolver); e != nil {
				return nil, false, e
			}
		}
	}
	if e = fullDeploymentSync(staged); e != nil {
		return nil, false, e
	}
	if e = fullDeploymentSync(s.root); e != nil {
		return nil, false, e
	}
	if bounded.Err() != nil {
		return nil, false, errors.New("prepared removal recovery deadline exceeded")
	}
	published, e = s.publishPreparedRemoval(fence, plan, staged)
	if published {
		return r, true, e
	}
	return nil, false, e
}

// A readable exchanged bundle is not proof that its directory publication was
// durable. Re-sync the exact state/history/root before any payload mutation or
// completed removal acknowledgment, including after a publication-sync error.
func (r *removalIntentStore) syncRemovalBarrier() (result error) {
	if e := r.verifyIntentMetadata(); e != nil {
		return e
	}
	s := r.store
	old, e := deploymentDirectory(s.root, r.fence.DisplacedRecord, s.owner, false)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, old.Close()) }()
	if e = s.phase("removal-barrier-before-state-sync"); e != nil {
		return e
	}
	if e = fullDeploymentSync(s.current); e != nil {
		return e
	}
	if e = s.phase("removal-barrier-before-history-sync"); e != nil {
		return e
	}
	if e = fullDeploymentSync(old); e != nil {
		return e
	}
	if e = sameDeploymentEntry(s.root, r.fence.DisplacedRecord, old, s.owner); e != nil {
		return e
	}
	if e = s.phase("removal-barrier-before-root-sync"); e != nil {
		return e
	}
	if e = fullDeploymentSync(s.root); e != nil {
		return e
	}
	if e = r.verifyIntentMetadata(); e != nil {
		return e
	}
	return s.phase("removal-barrier-durable")
}
