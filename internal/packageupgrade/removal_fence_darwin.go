//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

// Only private owned fixtures currently reach this primitive. It intentionally
// remains unavailable to CLI/package phases until deletion/reconciliation
// is implemented. Both existing leases must be held. The caller must use a
// freshly verified plan; this function publishes metadata, not deletion authority.
func (s *deploymentStore) publishRemovalFence(f removalFence, plan removalPlan) (published bool, result error) {
	if s == nil || s.current == nil || s.lock == nil || s.runtimeLock == nil {
		return false, errors.New("removal barrier requires an open leased store")
	}
	next, e := s.state.deactivate()
	if e != nil {
		return false, e
	}
	encoded, e := encodeDeployment(next)
	if e != nil {
		return false, e
	}
	if e = s.checkRemovalPreimage(f, plan, ""); e != nil {
		return false, e
	}
	planRaw, e := encodeRemovalPlan(plan)
	if e != nil {
		return false, e
	}
	marker, e := encodeRemovalFence(f, next)
	if e != nil {
		return false, e
	}
	entries, e := deploymentEntries(s.root, s.owner, maxRetainedRecords+4)
	if e != nil {
		return false, e
	}
	count := 0
	for _, entry := range entries {
		if recordName.MatchString(entry.Name()) {
			count++
		}
	}
	if count >= maxRetainedRecords {
		return false, errors.New("removal barrier history capacity exhausted")
	}
	preparation, e := s.openRemovalPreparationDirectory("")
	if e != nil {
		return false, e
	}
	defer func() { result = errors.Join(result, preparation.Close()) }()
	staged, e := darwintrust.CreateDirectoryAt(preparation, f.DisplacedRecord, s.owner)
	if e != nil {
		return false, e
	}
	defer func() {
		if !published {
			result = errors.Join(result, staged.Close())
		}
	}()
	if s.owner == 0 {
		if e = staged.Chown(0, 0); e != nil {
			return false, e
		}
	}
	if e = s.phase("removal-preparation-created"); e != nil {
		return false, e
	}
	for _, item := range []struct {
		name  string
		data  []byte
		phase string
	}{{deploymentRecord, encoded, "removal-state-durable"}, {removalPlanName, planRaw, "removal-plan-durable"}, {removalFenceName, marker, "removal-marker-durable"}} {
		file, e := darwintrust.CreateRegularAt(staged, item.name, s.owner)
		if e != nil {
			return false, e
		}
		if s.owner == 0 {
			if e = file.Chown(0, 0); e != nil {
				return false, errors.Join(e, file.Close())
			}
		}
		n, writeErr := file.Write(item.data)
		if writeErr == nil && n != len(item.data) {
			writeErr = io.ErrShortWrite
		}
		if e = errors.Join(writeErr, file.Chmod(0644), fullDeploymentSync(file), file.Close()); e != nil {
			return false, e
		}
		if e = s.phase(item.phase); e != nil {
			return false, e
		}
	}
	if e = errors.Join(staged.Chmod(0755), fullDeploymentSync(staged)); e != nil {
		return false, e
	}
	if e = s.phase("removal-directory-durable"); e != nil {
		return false, e
	}
	observed, observedPlan, actual, e := readRemovalBundle(staged, s.owner)
	if e != nil {
		return false, e
	}
	if observed != f || !bytes.Equal(actual, encoded) || sameRemovalPlans(plan, observedPlan) != nil {
		return false, errors.New("staged removal barrier changed")
	}
	if e = fullDeploymentSync(preparation); e != nil {
		return false, e
	}
	if e = s.phase("removal-preparation-durable"); e != nil {
		return false, e
	}
	if e = s.checkRemovalPreimage(f, plan, ""); e != nil {
		return false, e
	}
	if e = deploymentObject(preparation, true, s.owner, 0700); e != nil {
		return false, e
	}
	if e = sameDeploymentEntry(s.parent, removalPreparationRoot, preparation, s.owner); e != nil {
		return false, e
	}
	if e = sameDeploymentEntry(preparation, f.DisplacedRecord, staged, s.owner); e != nil {
		return false, e
	}
	// Only a complete durable bundle can enter authority history. This exclusive
	// move never overwrites an old record or falls back to copy/delete.
	if e = darwintrust.RenameEntryNoReplace(preparation, f.DisplacedRecord, s.root, f.DisplacedRecord); e != nil {
		return false, e
	}
	if e = s.phase("removal-record-reserved"); e != nil {
		return false, e
	}
	if e = errors.Join(fullDeploymentSync(preparation), fullDeploymentSync(s.root)); e != nil {
		return false, e
	}
	if e = s.phase("removal-reservation-parent-durable"); e != nil {
		return false, e
	}
	published, e = s.publishPreparedRemoval(f, plan, staged)
	return published, e
}
func readRemovalBundle(dir *os.File, owner uint32) (removalFence, removalPlan, []byte, error) {
	var zero removalFence
	var noPlan removalPlan
	fail := func(e error) (removalFence, removalPlan, []byte, error) { return zero, noPlan, nil, e }
	if e := deploymentObject(dir, true, owner, 0755); e != nil {
		return fail(e)
	}
	entries, e := deploymentEntries(dir, owner, 6)
	if e != nil {
		return fail(e)
	}
	if len(entries) < 3 || len(entries) > 6 {
		return fail(errors.New("removal bundle is incomplete"))
	}
	for _, entry := range entries {
		if entry.Name() != deploymentRecord && entry.Name() != removalFenceName && entry.Name() != removalPlanName && entry.Name() != removalJournalName && entry.Name() != removalQuarantineJournalName && entry.Name() != removalQuarantineName {
			return fail(errors.New("unknown removal bundle object"))
		}
	}
	read := func(name string) (result []byte, err error) {
		file, e := darwintrust.OpenRegularAt(dir, name, owner)
		if e != nil {
			return nil, e
		}
		defer func() { err = errors.Join(err, file.Close()) }()
		if e = deploymentObject(file, false, owner, 0644); e != nil {
			return nil, e
		}
		before, e := file.Stat()
		if e != nil {
			return nil, e
		}
		limit := int64(maxDeploymentRecord)
		if name == removalPlanName {
			limit = maxRemovalPlanBytes
		}
		if before.Size() <= 0 || before.Size() > limit {
			return nil, errors.New("removal bundle file exceeds budget")
		}
		data, e := io.ReadAll(io.LimitReader(file, limit+1))
		if e != nil {
			return nil, e
		}
		after, e := file.Stat()
		if e != nil {
			return nil, e
		}
		if !sameState(*before.Sys().(*syscall.Stat_t), *after.Sys().(*syscall.Stat_t)) || int64(len(data)) != before.Size() {
			return nil, errors.New("removal bundle changed while reading")
		}
		named, e := darwintrust.OpenRegularAt(dir, name, owner)
		if e != nil {
			return nil, e
		}
		namedInfo, statErr := named.Stat()
		closeErr := named.Close()
		if e = errors.Join(statErr, closeErr); e != nil {
			return nil, e
		}
		if !sameState(*before.Sys().(*syscall.Stat_t), *namedInfo.Sys().(*syscall.Stat_t)) {
			return nil, errors.New("removal bundle file name changed")
		}
		return data, nil
	}
	record, e := read(deploymentRecord)
	if e != nil {
		return fail(e)
	}
	marker, e := read(removalFenceName)
	if e != nil {
		return fail(e)
	}
	planRaw, e := read(removalPlanName)
	if e != nil {
		return fail(e)
	}
	fence, after, e := decodeRemovalFence(marker, record)
	if e != nil {
		return fail(e)
	}
	plan, e := decodeRemovalPlan(planRaw)
	if e != nil {
		return fail(e)
	}
	if e = fence.validatePlan(after, plan); e != nil {
		return fail(e)
	}
	actions, e := removalAllActions(plan)
	if e != nil {
		return fail(e)
	}
	_, _, progress, e := readRemovalJournalAt(dir, owner, removalJournalSeed(fence), len(actions))
	if e != nil {
		return fail(e)
	}
	_, _, quarantine, e := readRemovalQuarantineAt(dir, owner, fence, plan)
	if e != nil {
		return fail(e)
	}
	hasMoved := false
	for _, entry := range entries {
		if entry.Name() == removalQuarantineName {
			hasMoved = true
		}
	}
	started, mayBeAbsent, completed, e := removalQuarantinedRootState(plan, progress)
	if e != nil {
		return fail(e)
	}
	if started && quarantine.completed != 1 || hasMoved && !quarantine.pending && quarantine.completed != 1 || quarantine.completed == 1 && !hasMoved && !mayBeAbsent || completed && hasMoved {
		return fail(errors.New("quarantined entry differs from recorded move/removal intent"))
	}
	return fence, plan, record, nil
}
