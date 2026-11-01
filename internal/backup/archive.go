// Package backup encodes authenticated, password-encrypted profile snapshots.
// Machine policy, external files and live operating-system state are excluded.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/profile"
)

const HeaderBytes = 44
const Iterations = 600000
const MaxArchiveBytes = profile.MaxSnapshotBytes + HeaderBytes + 16
const magic = "AWBACKUP"

var ErrAuthentication = errors.New("backup authentication failed: wrong passphrase or damaged archive")

type Snapshot struct {
	SchemaVersion int               `json:"schemaVersion"`
	CreatedAt     time.Time         `json:"createdAt"`
	Profiles      []profile.Profile `json:"profiles"`
}

func passwordValid(password string) error {
	if !utf8.ValidString(password) || len(password) < 12 || len(password) > 1024 {
		return errors.New("backup passphrase must contain 12-1024 UTF-8 bytes")
	}
	return nil
}

func keyCipher(password string, salt []byte) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, Iterations, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Encrypt(profiles []profile.Profile, password string, createdAt time.Time) ([]byte, error) {
	if err := passwordValid(password); err != nil {
		return nil, err
	}
	if createdAt.IsZero() {
		return nil, errors.New("backup requires a creation timestamp")
	}
	if err := profile.ValidateSnapshot(profiles); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(Snapshot{1, createdAt.UTC(), profiles})
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	if len(plaintext) > profile.MaxSnapshotBytes {
		return nil, errors.New("backup exceeds snapshot size limit")
	}
	header := make([]byte, HeaderBytes)
	copy(header, magic)
	header[8], header[9], header[10] = 1, 1, 1 // version, PBKDF2-SHA256, AES-256-GCM
	binary.BigEndian.PutUint32(header[12:16], Iterations)
	if _, err := rand.Read(header[16:]); err != nil {
		return nil, err
	}
	aead, err := keyCipher(password, header[16:32])
	if err != nil {
		return nil, err
	}
	return aead.Seal(header, header[32:44], plaintext, header), nil
}

func Decrypt(data []byte, password string) (Snapshot, error) {
	var result Snapshot
	if err := passwordValid(password); err != nil {
		return result, err
	}
	// All algorithm/work-factor and allocation limits are checked before KDF.
	if len(data) < HeaderBytes+16 || len(data) > MaxArchiveBytes {
		return result, errors.New("backup size is outside supported limits")
	}
	header := data[:HeaderBytes]
	if string(header[:8]) != magic || header[8] != 1 || header[9] != 1 || header[10] != 1 || header[11] != 0 || binary.BigEndian.Uint32(header[12:16]) != Iterations {
		return result, errors.New("unsupported backup format or cryptographic parameters")
	}
	aead, err := keyCipher(password, header[16:32])
	if err != nil {
		return result, err
	}
	plaintext, err := aead.Open(nil, header[32:44], data[HeaderBytes:], header)
	if err != nil {
		return result, ErrAuthentication
	}
	defer clear(plaintext)
	if !utf8.Valid(plaintext) || strictSnapshot(plaintext) != nil {
		return Snapshot{}, errors.New("backup snapshot JSON is invalid")
	}
	// Authenticated bytes still require the current typed schema/limits.
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return Snapshot{}, errors.New("backup snapshot is invalid")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Snapshot{}, errors.New("backup must contain one snapshot")
	}
	if result.SchemaVersion != 1 || result.CreatedAt.IsZero() {
		return Snapshot{}, errors.New("unsupported backup snapshot schema")
	}
	if err := profile.ValidateSnapshot(result.Profiles); err != nil {
		return Snapshot{}, fmt.Errorf("invalid backup profiles: %w", err)
	}
	return result, nil
}
