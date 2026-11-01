package managed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrUnsupported = errors.New("managed policy installation is unsupported on this platform")

// InstallResult describes a committed local policy update, not full product qualification.
type InstallResult struct {
	Operation        string `json:"operation"`
	PreviousRevision uint64 `json:"previousRevision"`
	Revision         uint64 `json:"revision"`
	KeyID            string `json:"keyId"`
	PayloadSHA256    string `json:"payloadSHA256"`
	Committed        bool   `json:"committed"`
	Enforcement      string `json:"enforcement"`
}

// Install enrolls only an absent fixed machine source. The administrator must
// obtain expectedKey independently; an installation document cannot select trust.
func Install(data []byte, expectedKey ed25519.PublicKey) (InstallResult, error) {
	if _, _, err := installationTransition(nil, data, expectedKey, true, time.Now()); err != nil {
		return InstallResult{}, err
	}
	return applyMachineInstallation(data, expectedKey, true)
}

// Update uses only the key and last accepted revision from protected native
// state. Neither a caller-selected key nor a caller-selected floor is accepted.
func Update(envelope []byte) (InstallResult, error) {
	if len(envelope) == 0 || len(envelope) > MaxEnvelopeBytes {
		return InstallResult{}, errors.New("managed update envelope exceeds size limit or is empty")
	}
	return applyMachineInstallation(envelope, nil, false)
}

// Transactions publish the entire document on commit. No exported constructor
// accepts a replacement native backend or any fault-injection option.
type installationTransaction interface {
	Read() ([]byte, bool, error)
	Stage([]byte) error
	Commit() error
	Close() error
}

func commitInstallation(tx installationTransaction, next []byte, key ed25519.PublicKey, initial bool, clock func() time.Time) (result InstallResult, err error) {
	defer func() { err = errors.Join(err, tx.Close()) }()
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
	candidate, result, err := installationTransition(prior, next, key, initial, clock())
	if err != nil {
		return InstallResult{}, err
	}
	if err := tx.Stage(candidate); err != nil {
		return InstallResult{}, err
	}
	// Stage may wait on native contention. Never commit a candidate that expired
	// while that operation was pending. Close rolls back an uncommitted stage.
	if _, err := DecodeInstallation(candidate, clock()); err != nil {
		return InstallResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return InstallResult{}, fmt.Errorf("policy commit failed; inspect managed status before retrying: %w", err)
	}
	result.Committed = true
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
		installed, err := parseInstallation(prior)
		if err != nil {
			return nil, result, fmt.Errorf("cannot read prior enrolled policy: %w", err)
		}
		public, err := PublicKey(installed.PublicKey)
		if err != nil {
			return nil, result, err
		}
		envelope, err := json.Marshal(installed.Envelope)
		if err != nil {
			return nil, result, err
		}
		// Expiry must block runtime operations, but must not prevent renewal.
		// Authenticate the prior policy at its own issuance solely to recover
		// its key/revision metadata. This never constructs a runtime Authority.
		payload, err := canonicalBase64(installed.Envelope.Payload, 1, MaxPolicyBytes)
		if err != nil {
			return nil, result, err
		}
		var metadata Policy
		if err := strictJSON(payload, MaxPolicyBytes, &metadata); err != nil {
			return nil, result, err
		}
		verified, err := Verify(envelope, public, metadata.IssuedAt, installed.MinimumRevision)
		if err != nil {
			return nil, result, fmt.Errorf("cannot authenticate prior enrolled policy: %w", err)
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
