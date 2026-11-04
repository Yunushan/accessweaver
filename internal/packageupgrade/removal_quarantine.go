package packageupgrade

import (
	"encoding/json"
	"errors"
)

const removalQuarantineName = "public-app"
const removalQuarantineJournalName = "quarantine.jsonl"
const maxRemovalQuarantineBytes = 2 * maxRemovalJournalLine

// The one-action move log is bound to the complete immutable fence/plan and
// the actual destination directory vnode. It cannot authorize payload deletion.
func removalQuarantineSeed(f removalFence, plan removalPlan, device, inode uint64) (string, error) {
	if e := plan.validate(); e != nil {
		return "", e
	}
	raw, e := encodeRemovalPlan(plan)
	if e != nil || f.PlanSHA256 != removalDigest(raw) || inode == 0 || device != plan.Authority.RootDevice {
		return "", errors.New("invalid quarantine destination or plan binding")
	}
	next := deploymentState{SchemaVersion: 1, Generation: plan.Generation + 1, HighWaterVersion: plan.Active.Identity.Version, Pending: []deploymentPending{}}
	if e := f.validatePlan(next, plan); e != nil {
		return "", e
	}
	data, e := json.Marshal(struct {
		SchemaVersion int    `json:"schemaVersion"`
		FenceSHA256   string `json:"fenceSHA256"`
		Device        uint64 `json:"destinationDevice"`
		Inode         uint64 `json:"destinationInode"`
		Name          string `json:"destinationName"`
	}{1, removalJournalSeed(f), device, inode, removalQuarantineName})
	if e != nil {
		return "", e
	}
	return removalDigest(data), nil
}
