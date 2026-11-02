package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const MaxRecoveryBytes = 192 << 10
const maxRecoveryPayloadBytes = MaxEnvelopeBytes + 4096
const recoveryDomain = "AccessWeaver managed machine recovery v1\x00"
const maxRecoveryLifetime = 24 * time.Hour
const maxSafeRevision = (1 << 53) - 1

type recoveryRequest struct {
	SchemaVersion        int       `json:"schemaVersion"`
	PreviousSourceSHA256 string    `json:"previousSourceSHA256"`
	MinimumRevision      *uint64   `json:"minimumRevision"`
	IssuedAt             time.Time `json:"issuedAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
	NextEnvelope         Envelope  `json:"nextEnvelope"`
}

type RecoveryReview struct {
	PreviousSourceSHA256  string    `json:"previousSourceSHA256"`
	MinimumRevision       uint64    `json:"minimumRevision"`
	PreviousAuthenticated bool      `json:"previousAuthenticated"`
	PreviousRevision      uint64    `json:"previousRevision,omitempty"`
	PreviousKeyID         string    `json:"previousKeyId,omitempty"`
	ExpiresAt             time.Time `json:"expiresAt"`
	Next                  Verified  `json:"next"`
	PayloadSHA256         string    `json:"payloadSHA256"`
	SignatureValid        bool      `json:"signatureValid"`
	RuntimeEnforced       bool      `json:"runtimeEnforced"`
}

// An empty snapshot has a well-defined digest. Native recovery separately
// requires an existing, protected source; an approval cannot enroll absence.
func recoverySourceDigest(prior []byte) (string, error) {
	if len(prior) > MaxInstallationBytes {
		return "", errors.New("recovery prior machine source exceeds size limit")
	}
	digest := sha256.Sum256(prior)
	return hex.EncodeToString(digest[:]), nil
}
func recoveryFloor(minimum uint64) error {
	if minimum == 0 || minimum >= maxSafeRevision {
		return errors.New("recovery requires an independently recorded positive safe minimum revision below the maximum")
	}
	return nil
}

// ExportMachineSource reads the fixed protected source without granting runtime
// authority to its contents. It works for bounded corrupt JSON/signatures and
// existing empty values.
func ExportMachineSource() ([]byte, error) {
	if !machinePolicySupported() {
		return nil, ErrUnsupported
	}
	data, present, err := readMachineInstallation()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if !present {
		return nil, fmt.Errorf("%w: no enrolled source", ErrUnavailable)
	}
	if _, err := recoverySourceDigest(data); err != nil {
		return nil, err
	}
	return data, nil
}

// SignRecovery is an offline emergency approval for exactly one source snapshot
// and a newer policy signed by the independently pinned recovery key. It never
// derives a lost revision floor or trusted key from damaged bytes.
func SignRecovery(prior, next []byte, private ed25519.PrivateKey, minimum uint64, now time.Time, lifetime time.Duration) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]), private) {
		return nil, errors.New("invalid or inconsistent Ed25519 private key")
	}
	public := private.Public().(ed25519.PublicKey)
	if err := validatePublicKey(public); err != nil {
		return nil, err
	}
	if err := recoveryFloor(minimum); err != nil {
		return nil, err
	}
	source, err := recoverySourceDigest(prior)
	if err != nil {
		return nil, err
	}
	if now.IsZero() || lifetime <= 0 || lifetime > maxRecoveryLifetime {
		return nil, errors.New("recovery approval lifetime must be positive and at most 24 hours")
	}
	if _, err := PrepareInstallation(next, public, now, minimum); err != nil {
		return nil, err
	}
	var envelope Envelope
	if err := strictJSON(next, MaxEnvelopeBytes, &envelope); err != nil {
		return nil, err
	}
	request := recoveryRequest{1, source, &minimum, now.UTC(), now.Add(lifetime).UTC(), envelope}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxRecoveryPayloadBytes {
		return nil, errors.New("recovery payload exceeds size limit")
	}
	signed := Envelope{1, KeyID(public), base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(recoveryDomain), payload...)))}
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	// Review the same constraints as the receiving administrator before writing.
	if _, _, err := recoveryTransition(prior, data, public, minimum, now); err != nil {
		return nil, err
	}
	return data, nil
}

// VerifyRecovery is offline review. Both expectedKey and minimum must come from
// independent deployment records rather than the supplied recovery/source files.
func VerifyRecovery(prior, recovery []byte, expectedKey ed25519.PublicKey, minimum uint64, now time.Time) (RecoveryReview, error) {
	review, _, err := recoveryTransition(prior, recovery, expectedKey, minimum, now)
	return review, err
}
func recoveryTransition(prior, recovery []byte, expectedKey ed25519.PublicKey, minimum uint64, now time.Time) (RecoveryReview, []byte, error) {
	var review RecoveryReview
	if err := validatePublicKey(expectedKey); err != nil {
		return review, nil, err
	}
	if err := recoveryFloor(minimum); err != nil {
		return review, nil, err
	}
	source, err := recoverySourceDigest(prior)
	if err != nil {
		return review, nil, err
	}
	var envelope Envelope
	if err := strictJSON(recovery, MaxRecoveryBytes, &envelope); err != nil {
		return review, nil, err
	}
	if envelope.SchemaVersion != 1 || envelope.KeyID != KeyID(expectedKey) {
		return review, nil, errors.New("recovery does not match the independently supplied public key")
	}
	payload, err := canonicalBase64(envelope.Payload, 1, maxRecoveryPayloadBytes)
	if err != nil {
		return review, nil, errors.New("invalid recovery payload encoding or size")
	}
	signature, err := canonicalBase64(envelope.Signature, ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(expectedKey, append([]byte(recoveryDomain), payload...), signature) {
		return review, nil, errors.New("recovery signature verification failed")
	}
	var request recoveryRequest
	if err := strictJSON(payload, maxRecoveryPayloadBytes, &request); err != nil {
		return review, nil, err
	}
	if request.SchemaVersion != 1 || request.MinimumRevision == nil || *request.MinimumRevision != minimum || !digestPattern.MatchString(request.PreviousSourceSHA256) || request.PreviousSourceSHA256 != source {
		return review, nil, errors.New("recovery does not bind the exact machine source and independently supplied revision floor")
	}
	if now.IsZero() || request.IssuedAt.IsZero() || request.ExpiresAt.IsZero() || !request.ExpiresAt.After(request.IssuedAt) || request.ExpiresAt.Sub(request.IssuedAt) > maxRecoveryLifetime || now.Before(request.IssuedAt) || !now.Before(request.ExpiresAt) {
		return review, nil, errors.New("recovery approval is not currently valid or exceeds 24 hours")
	}
	floor := minimum
	if _, previous, err := authenticateInstallationHistory(prior); err == nil {
		review.PreviousAuthenticated = true
		review.PreviousRevision = previous.Policy.Revision
		review.PreviousKeyID = previous.KeyID
		if previous.Policy.Revision > floor {
			floor = previous.Policy.Revision
		}
	}
	nextEnvelope, err := json.Marshal(request.NextEnvelope)
	if err != nil {
		return review, nil, err
	}
	candidate, err := PrepareInstallation(nextEnvelope, expectedKey, now, floor)
	if err != nil {
		return review, nil, err
	}
	authority, err := DecodeInstallation(candidate, now)
	if err != nil {
		return review, nil, err
	}
	payloadHash := sha256.Sum256(payload)
	review.PreviousSourceSHA256 = source
	review.MinimumRevision = minimum
	review.ExpiresAt = request.ExpiresAt
	review.Next = authority.verified
	review.PayloadSHA256 = hex.EncodeToString(payloadHash[:])
	review.SignatureValid = true
	return review, candidate, nil
}

// Recover requires explicit native administrator rights and uses the ordinary
// protected transaction/compare-before-publication path. It cannot enroll an
// absent source or make the damaged source temporarily unmanaged.
func Recover(recovery []byte, expectedKey ed25519.PublicKey, minimum uint64) (InstallResult, error) {
	if len(recovery) == 0 || len(recovery) > MaxRecoveryBytes {
		return InstallResult{}, errors.New("recovery envelope is empty or exceeds size limit")
	}
	if err := validatePublicKey(expectedKey); err != nil {
		return InstallResult{}, err
	}
	if err := recoveryFloor(minimum); err != nil {
		return InstallResult{}, err
	}
	return applyMachineRecovery(recovery, expectedKey, minimum)
}
func commitRecovery(tx installationTransaction, recovery []byte, key ed25519.PublicKey, minimum uint64, clock func() time.Time) (result InstallResult, err error) {
	defer func() { err = errors.Join(err, tx.Close()) }()
	prior, present, err := tx.Read()
	if err != nil {
		return result, err
	}
	if !present {
		return result, errors.New("recovery cannot enroll an absent machine source")
	}
	review, candidate, err := recoveryTransition(prior, recovery, key, minimum, clock())
	if err != nil {
		return result, err
	}
	if err := tx.Stage(candidate); err != nil {
		return result, err
	}
	// A valid policy can outlive its much shorter emergency approval. Check both
	// windows again after waiting/staging, before committing any repair.
	if _, _, err := recoveryTransition(prior, recovery, key, minimum, clock()); err != nil {
		return result, err
	}
	result = InstallResult{Operation: "recover", PreviousKeyID: review.PreviousKeyID, PreviousRevision: review.PreviousRevision, Revision: review.Next.Policy.Revision, KeyID: review.Next.KeyID, PayloadSHA256: review.Next.PayloadSHA256, Enforcement: "partial", PreviousSourceSHA256: review.PreviousSourceSHA256, RecoveryPayloadSHA256: review.PayloadSHA256}
	committed, commitErr := commitPolicyTransaction(tx)
	result.Committed = committed
	if commitErr != nil {
		return result, fmt.Errorf("recovery commit failed; inspect managed status before retrying: %w", commitErr)
	}
	return result, nil
}
