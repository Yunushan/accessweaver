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
	fence, after, e := newRemovalFence(before, strings.Repeat("d", 64), strings.Repeat("e", 64))
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
			if _, _, e := newRemovalFence(state, desktop, strings.Repeat("e", 64)); e == nil {
				t.Fatal("unsafe barrier preparation accepted")
			}
		})
	}
}
