package packageupgrade

import (
	"encoding/json"
	"strings"
	"testing"
)

func removalFixture() (deploymentState, deploymentIdentity, []deploymentState) {
	old := deploymentFixtureSlot(1, "0.1.0")
	latest := deploymentFixtureSlot(2, "0.1.1")
	current := deploymentState{SchemaVersion: 1, Generation: 2, HighWaterVersion: latest.Identity.Version, Active: latest, Pending: []deploymentPending{}}
	previous := deploymentState{SchemaVersion: 1, Generation: 1, HighWaterVersion: old.Identity.Version, Active: old, Pending: []deploymentPending{{1, latest}}}
	return current, latest.Identity, []deploymentState{emptyDeployment(), previous}
}
func TestRemovalSlotsRequireProtectedCompleteUnambiguousHistory(t *testing.T) {
	current, identity, history := removalFixture()
	before, _ := json.Marshal(history)
	slots, e := removalSlots(current, identity, history)
	if e != nil || len(slots) != 2 || slots[0].ID >= slots[1].ID || slots[1] != current.Active {
		t.Fatal("valid bounded history refused", slots, e)
	}
	after, _ := json.Marshal(history)
	if string(before) != string(after) {
		t.Fatal("inspection changed history")
	}
	for _, kind := range []string{"inactive", "pending", "seal", "future-generation", "future-release", "conflicting-inode", "conflicting-seal", "invalid-history", "history-capacity", "slot-capacity"} {
		t.Run(kind, func(t *testing.T) {
			c, id, h := removalFixture()
			switch kind {
			case "inactive":
				c.Active = deploymentSlot{}
			case "pending":
				c.Pending = []deploymentPending{{c.Generation, deploymentFixtureSlot(3, id.Version)}}
			case "seal":
				id.PayloadSHA256 = strings.Repeat("f", 64)
			case "future-generation":
				h[1].Generation = c.Generation + 1
			case "future-release":
				h[1].HighWaterVersion = "0.2.0"
				h[1].Active.Identity.Version = "0.2.0"
			case "conflicting-inode":
				duplicate := c
				duplicate.Active.Inode++
				h = append(h, duplicate)
			case "conflicting-seal":
				duplicate := c
				duplicate.Active.Identity.ManifestSHA256 = strings.Repeat("f", 64)
				h = append(h, duplicate)
			case "invalid-history":
				h[0].Pending = nil
			case "history-capacity":
				h = make([]deploymentState, maxRetainedRecords+1)
			case "slot-capacity":
				h = nil
				for n := 1; n <= maxRetainedDeployments+1; n++ {
					state := c
					state.Active = deploymentFixtureSlot(n, id.Version)
					h = append(h, state)
				}
			}
			if _, e := removalSlots(c, id, h); e == nil {
				t.Fatal("unsafe removal ownership accepted")
			}
		})
	}
}

func TestRemovalInspectionDoesNotTreatEnvironmentAsSealOrDeletionAuthority(t *testing.T) {
	t.Setenv("ACCESSWEAVER_DESKTOP_RECORD_SHA256", strings.Repeat("a", 64))
	t.Setenv("ACCESSWEAVER_PRODUCT_COMPONENT", "application")
	result, e := InspectProductRemoval()
	if e == nil || result.MutationPerformed || result.ProductUninstallQualified || result.ProductionQualificationComplete {
		t.Fatal("unsealed or nonroot inspection accepted or claimed removal", result, e)
	}
}
