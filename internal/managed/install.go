package managed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type policyChange uint8

const (
	changeInstall policyChange = iota
	changeUpdate
	changeRotate
)

var ErrUnsupported = errors.New("managed policy installation is unsupported on this platform")

// InstallResult describes a committed local policy update, not full product qualification.
type InstallResult struct {
	PreviousSourceSHA256  string `json:"previousSourceSHA256,omitempty"`
	RecoveryPayloadSHA256 string `json:"recoveryPayloadSHA256,omitempty"`
	PreviousKeyID         string `json:"previousKeyId,omitempty"`
	Operation             string `json:"operation"`
	PreviousRevision      uint64 `json:"previousRevision"`
	Revision              uint64 `json:"revision"`
	KeyID                 string `json:"keyId"`
	PayloadSHA256         string `json:"payloadSHA256"`
	Committed             bool   `json:"committed"`
	Enforcement           string `json:"enforcement"`
}

// Install enrolls only an absent fixed machine source. The administrator must
// obtain expectedKey independently; an installation document cannot select trust.
func Install(data []byte, expectedKey ed25519.PublicKey) (InstallResult, error) {
	if _, _, err := installationTransition(nil, data, expectedKey, true, time.Now()); err != nil {
		return InstallResult{}, err
	}
	return applyMachinePolicy(data, expectedKey, changeInstall)
}

// Update uses only the key and last accepted revision from protected native
// state. Neither a caller-selected key nor a caller-selected floor is accepted.
func Update(envelope []byte) (InstallResult, error) {
	if len(envelope) == 0 || len(envelope) > MaxEnvelopeBytes {
		return InstallResult{}, errors.New("managed update envelope exceeds size limit or is empty")
	}
	return applyMachinePolicy(envelope, nil, changeUpdate)
}

// Transactions publish the entire document on commit. No exported constructor
// accepts a replacement native backend or any fault-injection option.
type installationTransaction interface {
	Read() ([]byte, bool, error)
	ReadAcceptance() ([]byte, bool, error)
	StageAccepted([]byte, []byte) error
	Stage([]byte) error
	Commit() error
	Close() error
}

func commitInstallation(tx installationTransaction, next []byte, key ed25519.PublicKey, change policyChange, clock func() time.Time) (result InstallResult, err error) {
	defer func() { err = errors.Join(err, tx.Close()) }()
	initial := change == changeInstall
	prior, present, err := tx.Read()
	if err != nil {
		return result, err
	}
	if initial && present {
		return result, errors.New("machine policy already exists; use managed update")
	}
	if !initial && !present {
		return result, errors.New("no enrolled machine policy; initial installation requires an independent public key")
	}
	record, recordPresent, err := tx.ReadAcceptance()
	if err != nil {
		return result, err
	}
	var accepted *acceptedHistory
	if !initial {
		accepted, err = transitionAcceptance(prior, record, recordPresent, false)
		if err != nil {
			return result, err
		}
	} else if recordPresent {
		return result, errors.New("accepted policy state already exists")
	}
	now := clock()
	var candidate []byte
	switch change {
	case changeInstall, changeUpdate:
		candidate, result, err = installationTransition(prior, next, key, initial, now)
	case changeRotate:
		candidate, result, err = rotationTransition(prior, next, now)
	default:
		return InstallResult{}, errors.New("unknown managed policy operation")
	}
	if err != nil {
		return InstallResult{}, err
	}
	if accepted != nil {
		if err := accepted.checkAdvance(candidate, now); err != nil {
			return InstallResult{}, err
		}
	}
	candidate, record, err = prepareNativeAcceptance(candidate, now)
	if err != nil {
		return InstallResult{}, err
	}
	if err := tx.StageAccepted(candidate, record); err != nil {
		return InstallResult{}, err
	}
	// Stage may wait on native contention. Never commit a candidate that expired
	// while that operation was pending. Close rolls back an uncommitted stage.
	if _, err := DecodeInstallation(candidate, clock()); err != nil {
		return InstallResult{}, err
	}
	committed, commitErr := commitPolicyTransaction(tx)
	result.Committed = committed
	if commitErr != nil {
		return result, fmt.Errorf("policy commit failed; inspect managed status before retrying: %w", commitErr)
	}
	return result, nil
}

func installationTransition(prior, next []byte, expectedKey ed25519.PublicKey, initial bool, now time.Time) ([]byte, InstallResult, error) {
	var result InstallResult
	candidate := next
	if initial {
		result.Operation = "install"
		installed, err := parseInstallation(candidate)
		if err != nil {
			return nil, result, err
		}
		public, err := PublicKey(installed.PublicKey)
		if err != nil || len(expectedKey) != ed25519.PublicKeySize || !bytes.Equal(public, expectedKey) {
			return nil, result, errors.New("installation key does not match the independently supplied public key")
		}
	} else {
		result.Operation = "update"
		public, verified, err := authenticateInstallationHistory(prior)
		if err != nil {
			return nil, result, err
		}
		result.PreviousRevision = verified.Policy.Revision
		candidate, err = PrepareInstallation(next, public, now, verified.Policy.Revision)
		if err != nil {
			return nil, result, err
		}
	}
	authority, err := DecodeInstallation(candidate, now)
	if err != nil {
		return nil, result, err
	}
	result.Revision = authority.verified.Policy.Revision
	result.KeyID = authority.verified.KeyID
	result.PayloadSHA256 = authority.verified.PayloadSHA256
	result.Enforcement = "partial"
	return candidate, result, nil
}

func authenticateInstallationHistory(data []byte) (ed25519.PublicKey, Verified, error) {
	installed, err := parseInstallation(data)
	if err != nil {
		return nil, Verified{}, fmt.Errorf("cannot read prior enrolled policy: %w", err)
	}
	public, err := PublicKey(installed.PublicKey)
	if err != nil {
		return nil, Verified{}, err
	}
	envelope, err := json.Marshal(installed.Envelope)
	if err != nil {
		return nil, Verified{}, err
	}
	payload, err := canonicalBase64(installed.Envelope.Payload, 1, MaxPolicyBytes)
	if err != nil {
		return nil, Verified{}, err
	}
	var metadata Policy
	if err := strictJSON(payload, MaxPolicyBytes, &metadata); err != nil {
		return nil, Verified{}, err
	}
	// Use issuance only to authenticate historical key/revision metadata. This
	// function does not create Authority or make expired permissions usable.
	verified, err := Verify(envelope, public, metadata.IssuedAt, installed.MinimumRevision)
	if err != nil {
		return nil, Verified{}, fmt.Errorf("cannot authenticate prior enrolled policy: %w", err)
	}
	return public, verified, nil
}

// ExportInstallation returns public, authenticated deployment data for an
// administrator to review offline. Expiry does not hide historical metadata.
func ExportInstallation() ([]byte, error) {
	if !machinePolicySupported() {
		return nil, ErrUnsupported
	}
	snapshot, err := readMachineSnapshot()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if !snapshot.present {
		return nil, fmt.Errorf("%w: no enrolled policy", ErrUnavailable)
	}
	if _, err := transitionAcceptance(snapshot.source, snapshot.acceptance, snapshot.acceptancePresent, false); err != nil {
		return nil, err
	}
	// Authenticated export retains expired history for administrator renewal.
	if _, _, err := authenticateInstallationHistory(snapshot.source); err != nil {
		return nil, err
	}
	return snapshot.source, nil
}

// Linux can publish by rename and then fail the directory durability sync. Keep
// that known publication visible to the operator even when Commit returns error.
func commitPolicyTransaction(tx installationTransaction) (bool, error) {
	err := tx.Commit()
	if err == nil {
		return true, nil
	}
	if outcome, ok := tx.(interface{ Published() bool }); ok {
		return outcome.Published(), err
	}
	return false, err
}
