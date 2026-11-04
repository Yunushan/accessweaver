package packageupgrade

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// This private barrier is not an uninstall command or a deletion capability.
// A future remover must first retain a complete verified mutation plan and
// implement reconciliation. Existing single-record readers refuse its pair.
const removalFenceName = "removal.json"

type removalFence struct {
	SchemaVersion       int            `json:"schemaVersion"`
	Operation           string         `json:"operation"`
	BaseGeneration      uint64         `json:"baseGeneration"`
	Target              deploymentSlot `json:"target"`
	DesktopRecordSHA256 string         `json:"desktopRecordSHA256"`
	InventorySHA256     string         `json:"inventorySHA256"`
	BeforeRecordSHA256  string         `json:"beforeRecordSHA256"`
}

func newRemovalFence(before deploymentState, desktopSHA, inventorySHA string) (removalFence, deploymentState, error) {
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
	return removalFence{1, "product-removal-intent", before.Generation, before.Active, desktopSHA, inventorySHA, removalDigest(raw)}, after, nil
}
func (f removalFence) validate(after deploymentState) error {
	if f.SchemaVersion != 1 || f.Operation != "product-removal-intent" || f.BaseGeneration == 0 || !hash.MatchString(f.DesktopRecordSHA256) || !hash.MatchString(f.InventorySHA256) || !hash.MatchString(f.BeforeRecordSHA256) {
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
