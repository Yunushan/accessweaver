package managed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const MaxInstallationBytes = 192 << 10

// Installation is one atomically deployed machine value. Its public key and
// revision floor are authority only after the native source verifies protection.
type Installation struct {
	SchemaVersion   int      `json:"schemaVersion"`
	PublicKey       string   `json:"publicKey"`
	MinimumRevision uint64   `json:"minimumRevision"`
	Envelope        Envelope `json:"envelope"`
}

// Authority has no exported mutable policy fields. Construction validates both
// the signature and validity window; native source protection is a separate check.
type Authority struct{ verified Verified }

func parseInstallation(data []byte) (Installation, error) {
	// The revision floor must be explicit; omission/null must not reset it to 0.
	var installed struct {
		SchemaVersion   int      `json:"schemaVersion"`
		PublicKey       string   `json:"publicKey"`
		MinimumRevision *uint64  `json:"minimumRevision"`
		Envelope        Envelope `json:"envelope"`
	}
	if err := strictJSON(data, MaxInstallationBytes, &installed); err != nil {
		return Installation{}, err
	}
	if installed.SchemaVersion != 1 {
		return Installation{}, errors.New("unsupported managed installation schema")
	}
	if installed.MinimumRevision == nil {
		return Installation{}, errors.New("managed installation requires an explicit revision floor")
	}
	return Installation{installed.SchemaVersion, installed.PublicKey, *installed.MinimumRevision, installed.Envelope}, nil
}

func DecodeInstallation(data []byte, now time.Time) (*Authority, error) {
	installed, err := parseInstallation(data)
	if err != nil {
		return nil, err
	}
	public, err := PublicKey(installed.PublicKey)
	if err != nil {
		return nil, err
	}
	envelope, err := json.Marshal(installed.Envelope)
	if err != nil {
		return nil, err
	}
	verified, err := Verify(envelope, public, now, installed.MinimumRevision)
	if err != nil {
		return nil, err
	}
	return &Authority{verified: verified}, nil
}

func PrepareInstallation(data []byte, public ed25519.PublicKey, now time.Time, minimum uint64) ([]byte, error) {
	if _, err := Verify(data, public, now, minimum); err != nil {
		return nil, err
	}
	var envelope Envelope
	if err := strictJSON(data, MaxEnvelopeBytes, &envelope); err != nil {
		return nil, err
	}
	result, err := json.MarshalIndent(Installation{1, base64.StdEncoding.EncodeToString(public), minimum, envelope}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(result, '\n'), nil
}

var ErrUnavailable = errors.New("managed machine policy is unavailable; ask the administrator to repair its configuration")
var ErrDenied = errors.New("operation denied by administrator policy")

// Current reads only the fixed native machine authority. User data roots,
// environment variables, profiles and browser input never select that source.
func Current() (*Authority, error) {
	data, present, err := readMachineInstallation()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if !present {
		return nil, nil
	}
	authority, err := DecodeInstallation(data, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return authority, nil
}

type Status struct {
	Supported   bool       `json:"supported"`
	Configured  bool       `json:"configured"`
	Valid       bool       `json:"valid"`
	Revision    uint64     `json:"revision,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	Enforcement string     `json:"enforcement"`
}

func MachineStatus() (Status, error) {
	result := Status{Supported: machinePolicySupported(), Enforcement: "none"}
	data, present, err := readMachineInstallation()
	result.Configured = present
	if err != nil {
		result.Enforcement = "blocked"
		return result, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if !present {
		return result, nil
	}
	authority, err := DecodeInstallation(data, time.Now())
	if err != nil {
		result.Enforcement = "blocked"
		return result, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	result.Valid = true
	result.Enforcement = "partial"
	result.Revision = authority.verified.Policy.Revision
	expires := authority.verified.Policy.ExpiresAt
	result.ExpiresAt = &expires
	// Native policy support remains partial until all input/service paths qualify.
	return result, nil
}
