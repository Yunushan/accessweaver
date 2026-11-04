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
	if e = f.validatePlan(next, plan); e != nil {
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
	if f.Target != s.state.Active || f.BaseGeneration != s.state.Generation || removalDigest(s.encoded) != f.BeforeRecordSHA256 || len(s.state.Pending) != 0 {
		return false, errors.New("removal barrier preimage differs")
	}
	if e = verifyRemovalPlanAuthority(s, plan.Authority); e != nil {
		return false, e
	}
	before, history, e := verifyRemovalPlanHistory(s, plan, "", "")
	if e != nil {
		return false, e
	}
	if e = verifyRemovalPlanSlots(s, plan, before, history); e != nil {
		return false, e
	}
	check := func() error {
		if e := s.checkRoot(); e != nil {
			return e
		}
		if e := sameDeploymentEntry(s.root, "state", s.current, s.owner); e != nil {
			return e
		}
		actual, e := s.readRecord(s.current)
		if e != nil {
			return e
		}
		if !bytes.Equal(actual, s.encoded) {
			return errors.New("removal barrier record changed")
		}
		return nil
	}
	if e = check(); e != nil {
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
	name := f.DisplacedRecord
	staged, e := darwintrust.CreateDirectoryAt(s.root, name, s.owner)
	if e != nil {
		return false, e
	}
	defer func() {
		if staged != nil {
			result = errors.Join(result, staged.Close())
		}
	}()
	if e = s.phase("removal-record-reserved"); e != nil {
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
	if e = sameDeploymentEntry(s.root, name, staged, s.owner); e != nil {
		return false, e
	}
	if e = check(); e != nil {
		return false, e
	}
	if _, _, e = verifyRemovalPlanHistory(s, plan, "", name); e != nil {
		return false, e
	}
	if e = verifyRemovalPlanAuthority(s, plan.Authority); e != nil {
		return false, e
	}
	if e = darwintrust.RenameDirectories(s.root, name, "state", true); e != nil {
		return false, e
	}
	old := s.current
	s.current = staged
	staged = nil
	s.state = next
	s.encoded = encoded
	closeErr := old.Close()
	if e = s.phase("removal-published"); e != nil {
		return true, errors.Join(e, closeErr)
	}
	if e = errors.Join(fullDeploymentSync(s.root), closeErr); e != nil {
		return true, e
	}
	return true, s.phase("removal-parent-durable")
}
func readRemovalBundle(dir *os.File, owner uint32) (removalFence, removalPlan, []byte, error) {
	var zero removalFence
	var noPlan removalPlan
	fail := func(e error) (removalFence, removalPlan, []byte, error) { return zero, noPlan, nil, e }
	if e := deploymentObject(dir, true, owner, 0755); e != nil {
		return fail(e)
	}
	entries, e := deploymentEntries(dir, owner, 3)
	if e != nil {
		return fail(e)
	}
	if len(entries) != 3 {
		return fail(errors.New("removal bundle is incomplete"))
	}
	for _, entry := range entries {
		if entry.Name() != deploymentRecord && entry.Name() != removalFenceName && entry.Name() != removalPlanName {
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
	return fence, plan, record, nil
}
