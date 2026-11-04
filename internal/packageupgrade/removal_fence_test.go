package packageupgrade

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func removalFenceState() deploymentState {
	slot := deploymentFixtureSlot(1, "0.1.1-alpha")
	return deploymentState{SchemaVersion: 1, Generation: 7, HighWaterVersion: slot.Identity.Version, Active: slot, Pending: []deploymentPending{}}
}
func TestRemovalFenceBindsExactPriorIdentityAndInactiveGeneration(t *testing.T) {
	before := removalFenceState()
	original, _ := encodeDeployment(before)
	fence, after, e := newRemovalFence(before, strings.Repeat("d", 64), strings.Repeat("e", 64), removalFencePlanForStateFixture(before))
	if e != nil {
		t.Fatal(e)
	}
	marker, e := encodeRemovalFence(fence, after)
	if e != nil {
		t.Fatal(e)
	}
	record, _ := encodeDeployment(after)
	decoded, state, e := decodeRemovalFence(marker, record)
	if e != nil || decoded != fence || state.Generation != 8 || state.Active != (deploymentSlot{}) || state.HighWaterVersion != before.HighWaterVersion || len(state.Pending) != 0 {
		t.Fatal("invalid removal barrier round trip", state, e)
	}
	unchanged, _ := encodeDeployment(before)
	if !bytes.Equal(original, unchanged) {
		t.Fatal("barrier mutated prior state")
	}
	for _, kind := range []string{"desktop", "inventory", "preimage", "operation", "target", "base", "generation", "active", "pending", "unknown", "duplicate", "noncanonical", "oversize", "empty"} {
		t.Run(kind, func(t *testing.T) {
			f, a := fence, after
			switch kind {
			case "desktop":
				f.DesktopRecordSHA256 = ""
			case "inventory":
				f.InventorySHA256 = "not-a-hash"
			case "preimage":
				f.BeforeRecordSHA256 = strings.Repeat("f", 64)
			case "operation":
				f.Operation = "delete-all"
			case "target":
				f.Target.Inode++
			case "base":
				f.BaseGeneration++
			case "generation":
				a.Generation++
			case "active":
				a.Active = before.Active
			case "pending":
				a.Pending = []deploymentPending{{a.Generation, deploymentFixtureSlot(2, "0.1.1-alpha")}}
			}
			raw, _ := json.Marshal(f)
			stateRaw, _ := json.Marshal(a)
			if kind == "unknown" {
				raw = append([]byte(`{"callerPath":"/tmp",`), raw[1:]...)
			}
			if kind == "duplicate" {
				raw = append([]byte(`{"schemaVersion":1,`), raw[1:]...)
			}
			if kind == "noncanonical" {
				raw = append([]byte(" "), raw...)
			}

			if kind == "oversize" {
				raw = bytes.Repeat([]byte(" "), maxDeploymentRecord+1)
			}
			if kind == "empty" {
				raw = nil
			}
			if _, _, e := decodeRemovalFence(raw, stateRaw); e == nil {
				t.Fatal("unbound removal barrier accepted")
			}
		})
	}
}
func TestRemovalFenceRefusesInactivePendingAndExhaustedGeneration(t *testing.T) {
	for _, kind := range []string{"inactive", "pending", "exhausted", "bad-seal"} {
		t.Run(kind, func(t *testing.T) {
			state := removalFenceState()
			desktop := strings.Repeat("d", 64)
			switch kind {
			case "inactive":
				state.Active = deploymentSlot{}
			case "pending":
				state.Pending = []deploymentPending{{state.Generation, deploymentFixtureSlot(2, "0.1.1-alpha")}}
			case "exhausted":
				state.Generation = math.MaxUint64
			case "bad-seal":
				desktop = ""
			}
			if _, _, e := newRemovalFence(state, desktop, strings.Repeat("e", 64), removalPlanFixture()); e == nil {
				t.Fatal("unsafe barrier preparation accepted")
			}
		})
	}
}

// This synthetic plan tests metadata publication only. It does not authorize
// deletion or stand in for the production protected filesystem capture.
func removalFencePlanForStateFixture(state deploymentState) removalPlan {
	p := removalPlanFixture()
	raw, _ := encodeDeployment(state)
	p.History = []removalRecord{{Name: "state", Device: 1, Inode: 999001, SHA256: removalDigest(raw)}}
	p.Generation = state.Generation
	p.Active = state.Active
	for i := range p.Roots {
		root := &p.Roots[i]
		if root.Kind == "core" {
			root.Key = state.Active.ID
			root.Identity = state.Active.Identity
		}
		if root.Kind == "incoming" {
			root.Key = state.Active.Identity.ManifestSHA256
			root.Identity = state.Active.Identity
		}
	}
	nonce := uint64(1000000)
	for i := range p.Roots {
		root := &p.Roots[i]
		for j := range root.Objects {
			o := &root.Objects[j]
			if root.Kind == "core" {
				o.Device = uint64(state.Active.Device)
			}
			nonce++
			if nonce == state.Active.Inode {
				nonce++
			}
			o.Inode = nonce
			if root.Kind == "core" && j == 0 {
				o.Inode = state.Active.Inode
			}
		}
	}
	return p
}
func TestRemovalFenceBindsPlanAndDisplacedStateName(t *testing.T) {
	before := removalFenceState()
	plan := removalFencePlanForStateFixture(before)
	fence, after, e := newRemovalFence(before, strings.Repeat("d", 64), strings.Repeat("e", 64), plan)
	if e != nil {
		t.Fatal(e)
	}
	if e = fence.validatePlan(after, plan); e != nil {
		t.Fatal(e)
	}
	raw, _ := encodeRemovalPlan(plan)
	if fence.SchemaVersion != 2 || fence.PlanSHA256 != removalDigest(raw) || !recordName.MatchString(fence.DisplacedRecord) {
		t.Fatal("plan/displacement not bound")
	}
	changed := fence
	changed.PlanSHA256 = strings.Repeat("f", 64)
	if e = changed.validatePlan(after, plan); e == nil {
		t.Fatal("substituted plan digest accepted")
	}
	changed = fence
	changed.DisplacedRecord = "../state"
	if _, e = encodeRemovalFence(changed, after); e == nil {
		t.Fatal("caller displacement path accepted")
	}
	for _, kind := range []string{"generation", "target", "desktop"} {
		t.Run(kind, func(t *testing.T) {
			p := removalFencePlanForStateFixture(before)
			switch kind {
			case "generation":
				p.Generation++
			case "target":
				p.Active.Inode++
			case "desktop":
				p.DesktopRecordSHA256 = strings.Repeat("b", 64)
			}
			if _, _, e := newRemovalFence(before, strings.Repeat("d", 64), strings.Repeat("e", 64), p); e == nil {
				t.Fatal("unrelated plan bound")
			}
		})
	}
}
