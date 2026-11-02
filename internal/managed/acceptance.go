package managed

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// One exact installation snapshot, base64-encoded, plus bounded format fields.
// This format is not authority by itself: the native store must verify protection
// and atomically publish it with the installation before it can supply a floor.
const maxAcceptanceBytes = ((MaxInstallationBytes+2)/3)*4 + 256

type acceptanceRecord struct {
	SchemaVersion int    `json:"schemaVersion"`
	Installation  string `json:"installation"`
}

// acceptedHistory authenticates historical key/revision information only.
// Expired permissions never become runtime authority through this type.
type acceptedHistory struct {
	source              []byte
	revision            uint64
	keyID, sourceSHA256 string
}

func prepareAcceptance(source []byte, now time.Time) ([]byte, error) {
	if _, err := DecodeInstallation(source, now); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(acceptanceRecord{1, base64.StdEncoding.EncodeToString(source)})
	if err != nil {
		return nil, err
	}
	if len(encoded)+1 > maxAcceptanceBytes {
		return nil, errors.New("accepted policy record exceeds size limit")
	}
	return append(encoded, '\n'), nil
}

func readAcceptance(data []byte) (*acceptedHistory, error) {
	var record acceptanceRecord
	if err := strictJSON(data, maxAcceptanceBytes, &record); err != nil {
		return nil, fmt.Errorf("%w: invalid accepted policy record: %w", ErrUnavailable, err)
	}
	if record.SchemaVersion != 1 {
		return nil, fmt.Errorf("%w: unsupported accepted policy record version", ErrUnavailable)
	}
	source, err := canonicalBase64(record.Installation, 1, MaxInstallationBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid accepted installation encoding: %w", ErrUnavailable, err)
	}
	_, history, err := authenticateInstallationHistory(source)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid accepted policy history: %w", ErrUnavailable, err)
	}
	hash := sha256.Sum256(source)
	return &acceptedHistory{source: source, revision: history.Policy.Revision, keyID: history.KeyID, sourceSHA256: hex.EncodeToString(hash[:])}, nil
}

func (accepted *acceptedHistory) checkSource(source []byte) error {
	if accepted == nil {
		return fmt.Errorf("%w: accepted policy history is unavailable", ErrUnavailable)
	}
	if !bytes.Equal(source, accepted.source) {
		return fmt.Errorf("%w: machine policy differs from the accepted source", ErrUnavailable)
	}
	return nil
}

func (accepted *acceptedHistory) checkAdvance(candidate []byte, now time.Time) error {
	if accepted == nil {
		return fmt.Errorf("%w: accepted policy history is unavailable", ErrUnavailable)
	}
	authority, err := DecodeInstallation(candidate, now)
	if err != nil {
		return err
	}
	if authority.verified.Policy.Revision <= accepted.revision {
		return fmt.Errorf("%w: replacement policy must exceed the last accepted revision", ErrDenied)
	}
	// Key changes require the separate rotation/recovery approval checks. This
	// revision check neither authorizes a new key nor chooses a recovery key.
	return nil
}

// machineSnapshot is populated only by fixed, protected native stores.
type machineSnapshot struct {
	source, acceptance         []byte
	present, acceptancePresent bool
}

func transitionAcceptance(source, record []byte, present, repair bool) (*acceptedHistory, error) {
	if !present && len(record) > 0 {
		return nil, fmt.Errorf("%w: inconsistent accepted policy presence", ErrUnavailable)
	}
	if present {
		accepted, err := readAcceptance(record)
		if err != nil {
			return nil, err
		}
		if !repair {
			if err := accepted.checkSource(source); err != nil {
				return nil, err
			}
		}
		return accepted, nil
	}
	installed, err := parseInstallation(source)
	if err == nil && installed.SchemaVersion == 2 {
		return nil, fmt.Errorf("%w: version-two storage requires its acceptance record", ErrUnavailable)
	}
	if err != nil && !repair {
		return nil, err
	}
	return nil, nil
}

func decodeMachineSnapshot(snapshot machineSnapshot, now time.Time) (*Authority, *acceptedHistory, error) {
	if !snapshot.present {
		if snapshot.acceptancePresent || len(snapshot.source) > 0 || len(snapshot.acceptance) > 0 {
			return nil, nil, fmt.Errorf("%w: inconsistent native policy presence", ErrUnavailable)
		}
		return nil, nil, nil
	}
	accepted, err := transitionAcceptance(snapshot.source, snapshot.acceptance, snapshot.acceptancePresent, false)
	if err != nil {
		return nil, nil, err
	}
	authority, err := DecodeInstallation(snapshot.source, now)
	return authority, accepted, err
}

func prepareNativeAcceptance(candidate []byte, now time.Time) ([]byte, []byte, error) {
	installed, err := parseInstallation(candidate)
	if err != nil {
		return nil, nil, err
	}
	installed.SchemaVersion = 2
	source, err := json.MarshalIndent(installed, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	source = append(source, '\n')
	record, err := prepareAcceptance(source, now)
	if err != nil {
		return nil, nil, err
	}
	return source, record, nil
}
