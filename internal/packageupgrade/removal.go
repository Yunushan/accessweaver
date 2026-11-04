package packageupgrade

import (
	"errors"
	"sort"
)

// ProductRemovalInspection is a read-only snapshot, never a deletion
// capability. A future remover must reacquire the leases and revalidate its
// complete mutation set, including incoming payloads and Installer receipts.
type ProductRemovalInspection struct {
	SchemaVersion                   int    `json:"schemaVersion"`
	Operation                       string `json:"operation"`
	State                           string `json:"state"`
	Version                         string `json:"version"`
	ManifestSHA256                  string `json:"manifestSHA256"`
	PayloadSHA256                   string `json:"payloadSHA256"`
	DesktopRecordSHA256             string `json:"desktopRecordSHA256"`
	Generation                      uint64 `json:"generation"`
	RetainedCoreCopies              int    `json:"retainedCoreCopies"`
	RetainedStateRecords            int    `json:"retainedStateRecords"`
	DesktopRegistrations            int    `json:"desktopRegistrations"`
	InventorySHA256                 string `json:"inventorySHA256"`
	InventoryScope                  string `json:"inventoryScope"`
	MutationPerformed               bool   `json:"mutationPerformed"`
	IncomingPayloadsInspected       bool   `json:"incomingPayloadsInspected"`
	InstallerReceiptsInspected      bool   `json:"installerReceiptsInspected"`
	ProductUninstallQualified       bool   `json:"productUninstallQualified"`
	ProductionQualificationComplete bool   `json:"productionQualificationComplete"`
}

// Historical pending records are evidence of ownership, not permission to
// delete a partial copy. Every resulting slot must still pass full native
// inventory verification. Never infer a slot identity from its own contents.
func removalSlots(current deploymentState, identity deploymentIdentity, history []deploymentState) ([]deploymentSlot, error) {
	if e := current.validate(); e != nil {
		return nil, e
	}
	if e := identity.validate(); e != nil {
		return nil, e
	}
	if current.Active == (deploymentSlot{}) || current.Active.Identity != identity || current.HighWaterVersion != identity.Version || len(current.Pending) != 0 {
		return nil, errors.New("removal inspection requires the exact active compiled release and no pending deployment")
	}
	if len(history) > maxRetainedRecords {
		return nil, errors.New("removal history exceeds capacity")
	}
	slots := map[string]deploymentSlot{}
	records := append([]deploymentState{current}, history...)
	for _, record := range records {
		if e := record.validate(); e != nil {
			return nil, e
		}
		if record.Generation > current.Generation {
			return nil, errors.New("retained removal history is newer than the active record")
		}
		if record.HighWaterVersion != "" {
			order, e := CompareVersions(record.HighWaterVersion, current.HighWaterVersion)
			if e != nil {
				return nil, e
			}
			if order > 0 {
				return nil, errors.New("retained removal high-water version is newer")
			}
		}
		candidates := []deploymentSlot{}
		if record.Active != (deploymentSlot{}) {
			candidates = append(candidates, record.Active)
		}
		for _, pending := range record.Pending {
			candidates = append(candidates, pending.Slot)
		}
		for _, slot := range candidates {
			order, e := CompareVersions(slot.Identity.Version, identity.Version)
			if e != nil {
				return nil, e
			}
			if order > 0 {
				return nil, errors.New("retained removal copy is newer than the compiled release")
			}
			if old, found := slots[slot.ID]; found && old != slot {
				return nil, errors.New("retained removal slot has conflicting protected identities")
			}
			slots[slot.ID] = slot
			if len(slots) > maxRetainedDeployments {
				return nil, errors.New("retained removal copies exceed capacity")
			}
		}
	}
	result := make([]deploymentSlot, 0, len(slots))
	for _, slot := range slots {
		result = append(result, slot)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
