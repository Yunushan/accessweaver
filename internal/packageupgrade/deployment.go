package packageupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
)

// Deployment records support the separate sealed root-only packaging tool.
// Apple package phases share this authority; public launcher integration remains pending.
// The generation is a removal fence as well as an activation sequence number.
const maxDeploymentPending = 8
const maxDeploymentRecord = 16384

var slotName = regexp.MustCompile(`^[a-f0-9]{32}$`)

const maxRetainedDeployments = 64
const maxRetainedRecords = 128

type deploymentIdentity struct {
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifestSHA256"`
	PayloadSHA256  string `json:"payloadSHA256"`
}
type deploymentSlot struct {
	ID       string             `json:"id"`
	Device   int64              `json:"device"`
	Inode    uint64             `json:"inode"`
	Identity deploymentIdentity `json:"identity"`
}
type deploymentPending struct {
	BaseGeneration uint64         `json:"baseGeneration"`
	Slot           deploymentSlot `json:"slot"`
}
type deploymentState struct {
	SchemaVersion    int    `json:"schemaVersion"`
	Generation       uint64 `json:"generation"`
	HighWaterVersion string `json:"highWaterVersion"`
	// An empty slot is a tombstone, never a request to reconstruct from receipt
	// metadata or a directory that merely looks like an installed application.
	Active  deploymentSlot      `json:"active"`
	Pending []deploymentPending `json:"pending"`
}

func emptyDeployment() deploymentState {
	return deploymentState{SchemaVersion: 1, Pending: []deploymentPending{}}
}
func (i deploymentIdentity) validate() error {
	if _, e := version(i.Version); e != nil {
		return e
	}
	if !hash.MatchString(i.ManifestSHA256) || !hash.MatchString(i.PayloadSHA256) {
		return errors.New("deployment seal is invalid")
	}
	return nil
}
func (s deploymentSlot) validate() error {
	if !slotName.MatchString(s.ID) || s.Inode == 0 {
		return errors.New("deployment slot identity is invalid")
	}
	return s.Identity.validate()
}
func (s deploymentState) validate() error {
	if s.SchemaVersion != 1 || s.Pending == nil || len(s.Pending) > maxDeploymentPending {
		return errors.New("deployment state extent/schema differs")
	}
	if s.HighWaterVersion != "" {
		if _, e := version(s.HighWaterVersion); e != nil {
			return e
		}
	}
	if s.Active != (deploymentSlot{}) {
		if e := s.Active.validate(); e != nil {
			return e
		}
		if s.Generation == 0 || s.Active.Identity.Version != s.HighWaterVersion {
			return errors.New("active deployment/high-water identity differs")
		}
	}
	if (s.Generation == 0) != (s.HighWaterVersion == "") {
		return errors.New("deployment history is inconsistent")
	}
	seen := map[string]bool{}
	for _, p := range s.Pending {
		if e := p.Slot.validate(); e != nil {
			return e
		}
		if p.BaseGeneration > s.Generation || seen[p.Slot.ID] || p.Slot.ID == s.Active.ID {
			return errors.New("pending deployment history is ambiguous")
		}
		seen[p.Slot.ID] = true
	}
	return nil
}
func encodeDeployment(s deploymentState) ([]byte, error) {
	if e := s.validate(); e != nil {
		return nil, e
	}
	data, e := json.Marshal(s)
	if len(data) > maxDeploymentRecord {
		return nil, errors.New("deployment record exceeds limit")
	}
	return data, e
}
func decodeDeployment(data []byte) (deploymentState, error) {
	var s deploymentState
	if len(data) > maxDeploymentRecord {
		return s, errors.New("deployment record exceeds limit")
	}
	if e := strict(data, &s); e != nil {
		return s, e
	}
	encoded, e := encodeDeployment(s)
	if e != nil {
		return s, e
	}
	// Exact encoding also rejects omitted fields, alternate numeric encodings,
	// escaped keys and whitespace variants rather than guessing intent.
	if !bytes.Equal(data, encoded) {
		return s, errors.New("noncanonical deployment record")
	}
	return s, nil
}
func (s deploymentState) canPrepare(identity deploymentIdentity) error {
	if e := s.validate(); e != nil {
		return e
	}
	if e := identity.validate(); e != nil {
		return e
	}
	if s.Generation == math.MaxUint64 || len(s.Pending) == maxDeploymentPending {
		return errors.New("deployment transaction capacity exhausted")
	}
	if s.HighWaterVersion != "" {
		if _, e := decision(identity.Version, s.HighWaterVersion); e != nil {
			return e
		}
	}
	return nil
}
func (s deploymentState) prepare(slot deploymentSlot) (deploymentState, error) {
	if e := s.canPrepare(slot.Identity); e != nil {
		return s, e
	}
	if e := slot.validate(); e != nil {
		return s, e
	}
	if s.Active.ID == slot.ID {
		return s, errors.New("active slot cannot be prepared again")
	}
	for _, p := range s.Pending {
		if p.Slot.ID == slot.ID {
			return s, errors.New("slot is already prepared")
		}
	}
	s.Pending = append(append([]deploymentPending{}, s.Pending...), deploymentPending{s.Generation, slot})
	return s, nil
}
func (s deploymentState) activate(slot deploymentSlot) (deploymentState, error) {
	if e := s.validate(); e != nil {
		return s, e
	}
	if s.Generation == math.MaxUint64 {
		return s, errors.New("deployment generation exhausted")
	}
	found := -1
	for i, p := range s.Pending {
		if p.Slot == slot && p.BaseGeneration == s.Generation {
			found = i
			break
		}
	}
	if found < 0 {
		return s, errors.New("deployment is absent, changed or fenced by a newer operation")
	}
	if s.HighWaterVersion != "" {
		if _, e := decision(slot.Identity.Version, s.HighWaterVersion); e != nil {
			return s, e
		}
	}
	s.Pending = append(append([]deploymentPending{}, s.Pending[:found]...), s.Pending[found+1:]...)
	s.Generation++
	s.HighWaterVersion = slot.Identity.Version
	s.Active = slot
	return s, nil
}
func (s deploymentState) deactivate() (deploymentState, error) {
	if e := s.validate(); e != nil {
		return s, e
	}
	// Do not erase the high-water release or advance an empty never-installed
	// store. Every removal of an active generation invalidates old prepares.
	if s.Active == (deploymentSlot{}) {
		return s, errors.New("there is no active deployment")
	}
	if s.Generation == math.MaxUint64 {
		return s, errors.New("deployment generation exhausted")
	}
	s.Generation++
	s.Active = deploymentSlot{}
	return s, nil
}
func (s deploymentState) abandon(id string) (deploymentState, error) {
	if e := s.validate(); e != nil {
		return s, e
	}
	for i, p := range s.Pending {
		if p.Slot.ID == id {
			s.Pending = append(append([]deploymentPending{}, s.Pending[:i]...), s.Pending[i+1:]...)
			return s, nil
		}
	}
	return s, errors.New("pending deployment does not exist")
}
