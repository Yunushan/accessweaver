//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"errors"
	"os"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// This handle validates protected intent metadata only. A future mutation
// engine must separately reconcile every payload/receipt object and known
// absence. Neither constructor nor returned handle authorizes deletion.
type removalIntentStore struct {
	store *deploymentStore
	fence removalFence
	plan  removalPlan
}

func (r *removalIntentStore) Close() error { return r.store.Close() }

// Parent ownership transfers on every path. No coordination or metadata file
// is created. Runtime callers will use fixed compiled seals/root; alternate
// parent/owner inputs are private owned-fixture facilities.
func openRemovalIntentAt(parent *os.File, owner uint32, identity deploymentIdentity, desktopSHA string) (*removalIntentStore, error) {
	s := &deploymentStore{parent: parent, owner: owner}
	fail := func(e error) (*removalIntentStore, error) { return nil, errors.Join(e, s.Close()) }
	if e := identity.validate(); e != nil {
		return fail(e)
	}
	if !hash.MatchString(desktopSHA) {
		return fail(errors.New("invalid compiled removal desktop seal"))
	}
	if _, e := darwintrust.Check(parent, true, owner); e != nil {
		return fail(e)
	}
	var e error
	s.root, e = deploymentDirectory(parent, deploymentRoot, owner, false)
	if e != nil {
		return fail(e)
	}
	entries, e := deploymentEntries(s.root, owner, maxRetainedRecords+4)
	if e != nil {
		return fail(e)
	}
	required := map[string]bool{deploymentLock: false, runtimeLeaseName: false, "state": false, "versions": false}
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := required[name]; ok {
			required[name] = true
		} else if !recordName.MatchString(name) {
			return fail(errors.New("unknown removal authority object"))
		}
	}
	for _, present := range required {
		if !present {
			return fail(errors.New("removal coordination or authority metadata is absent"))
		}
	}
	s.lock, e = darwintrust.OpenRegularAt(s.root, deploymentLock, owner)
	if e != nil {
		return fail(e)
	}
	if e = deploymentObject(s.lock, false, owner, 0600); e != nil {
		return fail(e)
	}
	info, e := s.lock.Stat()
	if e != nil {
		return fail(e)
	}
	if info.Size() != 0 {
		return fail(errors.New("removal coordination file is not empty"))
	}
	if e = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fail(errors.New("removal writer is busy"))
	}
	if e = s.checkRoot(); e != nil {
		return fail(e)
	}
	s.runtimeLock, e = runtimeFileAt(s.root, owner)
	if e != nil {
		return fail(e)
	}
	if e = unix.Flock(int(s.runtimeLock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fail(errors.New("removal runtime lease is busy"))
	}
	s.versions, e = deploymentDirectory(s.root, "versions", owner, false)
	if e != nil {
		return fail(e)
	}
	s.current, e = deploymentDirectory(s.root, "state", owner, false)
	if e != nil {
		return fail(e)
	}
	fence, plan, encoded, e := readRemovalBundle(s.current, owner)
	if e != nil {
		return fail(e)
	}
	if fence.Target.Identity != identity || fence.DesktopRecordSHA256 != desktopSHA {
		return fail(errors.New("removal intent differs from compiled release"))
	}
	if e = verifyRemovalPlanAuthority(s, plan.Authority); e != nil {
		return fail(e)
	}
	s.state, e = decodeDeployment(encoded)
	if e != nil {
		return fail(e)
	}
	s.encoded = encoded
	before, history, e := verifyRemovalPlanHistory(s, plan, fence.DisplacedRecord, "")
	if e != nil {
		return fail(e)
	}
	beforeRaw, e := encodeDeployment(before)
	if e != nil {
		return fail(e)
	}
	if removalDigest(beforeRaw) != fence.BeforeRecordSHA256 {
		return fail(errors.New("removal displaced preimage differs"))
	}
	if e = verifyRemovalPlanSlots(s, plan, before, history); e != nil {
		return fail(e)
	}
	again, againPlan, againEncoded, e := readRemovalBundle(s.current, owner)
	if e != nil {
		return fail(e)
	}
	if again != fence || !bytes.Equal(encoded, againEncoded) || sameRemovalPlans(plan, againPlan) != nil {
		return fail(errors.New("removal intent changed during reopening"))
	}
	checkedBefore, checkedHistory, e := verifyRemovalPlanHistory(s, plan, fence.DisplacedRecord, "")
	if e != nil {
		return fail(e)
	}
	if e = verifyRemovalPlanSlots(s, plan, checkedBefore, checkedHistory); e != nil {
		return fail(e)
	}
	if e = sameDeploymentEntry(s.root, "state", s.current, owner); e != nil {
		return fail(e)
	}
	if e = s.checkRoot(); e != nil {
		return fail(e)
	}
	return &removalIntentStore{store: s, fence: fence, plan: plan}, nil
}

// Before publication the original state is named "state". Afterwards the
// exact reserved displacement name locates that same vnode and bytes.
// A currently held staging directory may be excluded during the final check.
func verifyRemovalPlanHistory(s *deploymentStore, plan removalPlan, displaced, staging string) (deploymentState, []deploymentState, error) {
	var before deploymentState
	fail := func(e error) (deploymentState, []deploymentState, error) { return before, nil, e }
	if e := plan.validate(); e != nil {
		return fail(e)
	}
	if displaced != "" && !recordName.MatchString(displaced) || staging != "" && !recordName.MatchString(staging) {
		return fail(errors.New("invalid private removal history mapping"))
	}
	expected := map[string]removalRecord{}
	for _, record := range plan.History {
		name := record.Name
		if name == "state" && displaced != "" {
			name = displaced
		}
		if _, ok := expected[name]; ok || name == staging {
			return fail(errors.New("ambiguous removal history mapping"))
		}
		expected[name] = record
	}
	entries, e := deploymentEntries(s.root, s.owner, maxRetainedRecords+4)
	if e != nil {
		return fail(e)
	}
	found := 0
	history := []deploymentState{}
	for _, entry := range entries {
		name := entry.Name()
		if name == deploymentLock || name == runtimeLeaseName || name == "versions" || name == "state" && displaced != "" || name == staging {
			continue
		}
		binding, ok := expected[name]
		if !ok {
			return fail(errors.New("removal history inventory changed"))
		}
		dir, e := deploymentDirectory(s.root, name, s.owner, false)
		if e != nil {
			return fail(e)
		}
		raw, readErr := s.readRecord(dir)
		info, statErr := dir.Stat()
		sameErr := sameDeploymentEntry(s.root, name, dir, s.owner)
		if e = errors.Join(readErr, statErr, sameErr, dir.Close()); e != nil {
			return fail(e)
		}
		state, e := decodeDeployment(raw)
		if e != nil {
			return fail(e)
		}
		st := info.Sys().(*syscall.Stat_t)
		if uint64(st.Dev) != binding.Device || st.Ino != binding.Inode || removalDigest(raw) != binding.SHA256 {
			return fail(errors.New("removal history identity or bytes changed"))
		}
		found++
		if binding.Name == "state" {
			before = state
		} else {
			history = append(history, state)
		}
	}
	if found != len(expected) || before.Generation != plan.Generation || before.Active != plan.Active || len(before.Pending) != 0 {
		return fail(errors.New("removal original generation is absent or changed"))
	}
	return before, history, nil
}
func verifyRemovalPlanSlots(s *deploymentStore, plan removalPlan, before deploymentState, history []deploymentState) error {
	slots, e := removalSlots(before, plan.Active.Identity, history)
	if e != nil {
		return e
	}
	info, e := s.versions.Stat()
	if e != nil {
		return e
	}
	parent := info.Sys().(*syscall.Stat_t)
	expected := map[string]deploymentSlot{}
	for _, slot := range slots {
		expected[slot.ID] = slot
	}
	count := 0
	for _, root := range plan.Roots {
		if root.Kind != "core" {
			continue
		}
		count++
		slot, ok := expected[root.Key]
		first := root.Objects[0]
		if !ok || root.Identity != slot.Identity || first.Device != uint64(slot.Device) || first.Inode != slot.Inode || root.ParentDevice != uint64(parent.Dev) || root.ParentInode != parent.Ino {
			return errors.New("removal plan differs from protected slot history or versions parent")
		}
	}
	if count != len(expected) {
		return errors.New("removal plan omits protected core history")
	}
	return nil
}

func captureRemovalPlanAuthority(s *deploymentStore) (result removalPlanAuthority, err error) {
	if s == nil || s.root == nil || s.lock == nil || s.runtimeLock == nil {
		return result, errors.New("removal authority is not leased")
	}
	values := make([][2]uint64, 0, 3)
	for _, file := range []*os.File{s.root, s.lock, s.runtimeLock} {
		info, e := file.Stat()
		if e != nil {
			return result, e
		}
		st := info.Sys().(*syscall.Stat_t)
		values = append(values, [2]uint64{uint64(st.Dev), st.Ino})
	}
	return removalPlanAuthority{values[0][0], values[0][1], values[1][0], values[1][1], values[2][0], values[2][1]}, nil
}
func verifyRemovalPlanAuthority(s *deploymentStore, want removalPlanAuthority) error {
	if e := s.checkRoot(); e != nil {
		return e
	}
	actual, e := captureRemovalPlanAuthority(s)
	if e != nil {
		return e
	}
	if actual != want {
		return errors.New("removal authority or coordination identity changed")
	}
	return nil
}
