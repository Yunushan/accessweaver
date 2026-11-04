package packageupgrade

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// This private barrier is not an uninstall command or a deletion capability.
// The private publisher binds a complete plan; a future remover still needs
// filesystem reconciliation. Existing single-record readers refuse the bundle.
const removalFenceName = "removal.json"
const removalPlanName = "plan.json"

type removalFence struct {
	SchemaVersion       int            `json:"schemaVersion"`
	Operation           string         `json:"operation"`
	BaseGeneration      uint64         `json:"baseGeneration"`
	Target              deploymentSlot `json:"target"`
	DesktopRecordSHA256 string         `json:"desktopRecordSHA256"`
	InventorySHA256     string         `json:"inventorySHA256"`
	BeforeRecordSHA256  string         `json:"beforeRecordSHA256"`
	PlanSHA256          string         `json:"planSHA256"`
	DisplacedRecord     string         `json:"displacedRecord"`
}

func newRemovalFence(before deploymentState, desktopSHA, inventorySHA string, plan removalPlan) (removalFence, deploymentState, error) {
	var zero removalFence
	if e := before.validate(); e != nil {
		return zero, before, e
	}
	if before.Active == (deploymentSlot{}) || len(before.Pending) != 0 || !hash.MatchString(desktopSHA) || !hash.MatchString(inventorySHA) {
		return zero, before, errors.New("removal barrier requires an exact active inventory and no pending operation")
	}
	after, e := before.deactivate()
	if e != nil {
		return zero, before, e
	}
	raw, e := encodeDeployment(before)
	if e != nil {
		return zero, before, e
	}

	planRaw, e := encodeRemovalPlan(plan)
	if e != nil {
		return zero, before, e
	}
	if plan.Generation != before.Generation || plan.Active != before.Active || plan.DesktopRecordSHA256 != desktopSHA {
		return zero, before, errors.New("removal plan identity differs from active generation")
	}
	nonce, e := randomDeploymentName()
	if e != nil {
		return zero, before, e
	}
	return removalFence{SchemaVersion: 2, Operation: "product-removal-intent", BaseGeneration: before.Generation, Target: before.Active, DesktopRecordSHA256: desktopSHA, InventorySHA256: inventorySHA, BeforeRecordSHA256: removalDigest(raw), PlanSHA256: removalDigest(planRaw), DisplacedRecord: ".record-" + nonce}, after, nil
}
func (f removalFence) validate(after deploymentState) error {
	if f.SchemaVersion != 2 || f.Operation != "product-removal-intent" || f.BaseGeneration == 0 || !hash.MatchString(f.DesktopRecordSHA256) || !hash.MatchString(f.InventorySHA256) || !hash.MatchString(f.BeforeRecordSHA256) || !hash.MatchString(f.PlanSHA256) || !recordName.MatchString(f.DisplacedRecord) {
		return errors.New("invalid removal barrier identity")
	}
	if e := f.Target.validate(); e != nil {
		return e
	}
	before := deploymentState{SchemaVersion: 1, Generation: f.BaseGeneration, HighWaterVersion: f.Target.Identity.Version, Active: f.Target, Pending: []deploymentPending{}}
	expected, e := before.deactivate()
	if e != nil {
		return e
	}
	raw, e := encodeDeployment(before)
	if e != nil {
		return e
	}
	got, e := encodeDeployment(after)
	if e != nil {
		return e
	}
	want, _ := encodeDeployment(expected)
	if removalDigest(raw) != f.BeforeRecordSHA256 || !bytes.Equal(got, want) {
		return errors.New("removal barrier does not bind the exact inactive generation")
	}
	return nil
}
func encodeRemovalFence(f removalFence, after deploymentState) ([]byte, error) {
	if e := f.validate(after); e != nil {
		return nil, e
	}
	data, e := json.Marshal(f)
	if len(data) > maxDeploymentRecord {
		return nil, errors.New("removal barrier exceeds metadata budget")
	}
	return data, e
}
func decodeRemovalFence(data, record []byte) (removalFence, deploymentState, error) {
	var f removalFence
	if len(data) == 0 || len(data) > maxDeploymentRecord {
		return f, deploymentState{}, errors.New("removal barrier exceeds metadata budget")
	}
	after, e := decodeDeployment(record)
	if e != nil {
		return f, after, e
	}
	if e = strict(data, &f); e != nil {
		return f, after, e
	}
	canonical, e := encodeRemovalFence(f, after)
	if e != nil {
		return f, after, e
	}
	if !bytes.Equal(canonical, data) {
		return f, after, errors.New("noncanonical removal barrier")
	}
	return f, after, nil
}

func removalDigest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

// Bundle validation authenticates relationships within canonical protected
// metadata. It does not reconcile current payload objects or permit mutation.
func (f removalFence) validatePlan(after deploymentState, plan removalPlan) error {
	if e := f.validate(after); e != nil {
		return e
	}
	for _, record := range plan.History {
		if record.Name == f.DisplacedRecord {
			return errors.New("removal displacement conflicts with retained history")
		}
	}
	raw, e := encodeRemovalPlan(plan)
	if e != nil {
		return e
	}
	if removalDigest(raw) != f.PlanSHA256 || plan.Generation != f.BaseGeneration || plan.Active != f.Target || plan.DesktopRecordSHA256 != f.DesktopRecordSHA256 {
		return errors.New("removal plan is not bound by intent")
	}
	return nil
}
