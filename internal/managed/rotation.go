package managed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const MaxRotationPayloadBytes = MaxEnvelopeBytes + 4096
const MaxRotationBytes = 192 << 10
const rotationDomain = "AccessWeaver managed key rotation v1\x00"

type rotationRequest struct {
	SchemaVersion         int      `json:"schemaVersion"`
	PreviousKeyID         string   `json:"previousKeyId"`
	PreviousRevision      uint64   `json:"previousRevision"`
	PreviousPayloadSHA256 string   `json:"previousPayloadSHA256"`
	NextPublicKey         string   `json:"nextPublicKey"`
	NextEnvelope          Envelope `json:"nextEnvelope"`
}

type RotationReview struct {
	PreviousKeyID         string   `json:"previousKeyId"`
	PreviousRevision      uint64   `json:"previousRevision"`
	PreviousPayloadSHA256 string   `json:"previousPayloadSHA256"`
	Next                  Verified `json:"next"`
	SignatureValid        bool     `json:"signatureValid"`
	RuntimeEnforced       bool     `json:"runtimeEnforced"`
}

// SignRotation uses the old private key to authorize one exact new policy and
// key, bound to the authenticated previous revision and policy payload hash.
// The new policy's own signature proves possession of the new signing key.
func SignRotation(prior, next []byte, nextPublic ed25519.PublicKey, oldPrivate ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(oldPrivate) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(oldPrivate[:ed25519.SeedSize]), oldPrivate) {
		return nil, errors.New("inconsistent Ed25519 private key")
	}
	oldPublic, previous, err := authenticateInstallationHistory(prior)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(oldPublic, oldPrivate.Public().(ed25519.PublicKey)) {
		return nil, errors.New("rotation signer does not match the previous enrolled key")
	}
	if len(nextPublic) != ed25519.PublicKeySize || bytes.Equal(oldPublic, nextPublic) {
		return nil, errors.New("rotation requires a different Ed25519 public key")
	}
	if _, err := Verify(next, nextPublic, now, previous.Policy.Revision); err != nil {
		return nil, err
	}
	var nextEnvelope Envelope
	if err := strictJSON(next, MaxEnvelopeBytes, &nextEnvelope); err != nil {
		return nil, err
	}
	request := rotationRequest{1, previous.KeyID, previous.Policy.Revision, previous.PayloadSHA256, base64.StdEncoding.EncodeToString(nextPublic), nextEnvelope}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxRotationPayloadBytes {
		return nil, errors.New("rotation payload exceeds size limit")
	}
	signature := ed25519.Sign(oldPrivate, append([]byte(rotationDomain), payload...))
	data, err := json.MarshalIndent(Envelope{1, previous.KeyID, base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(signature)}, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > MaxRotationBytes {
		return nil, errors.New("rotation exceeds size limit")
	}
	return data, nil
}

// VerifyRotation is offline review. expectedCurrentKey must come from the
// operator's independent trusted channel, not from the supplied prior file.
func VerifyRotation(prior, rotation []byte, expectedCurrentKey ed25519.PublicKey, now time.Time) (RotationReview, error) {
	public, _, err := authenticateInstallationHistory(prior)
	if err != nil {
		return RotationReview{}, err
	}
	if len(expectedCurrentKey) != ed25519.PublicKeySize || !bytes.Equal(public, expectedCurrentKey) {
		return RotationReview{}, errors.New("previous installation does not match the independently pinned key")
	}
	checked, err := verifyRotation(prior, rotation, now)
	return checked.review, err
}

type authenticatedRotation struct {
	review       RotationReview
	nextPublic   ed25519.PublicKey
	nextEnvelope []byte
}

func verifyRotation(prior, rotation []byte, now time.Time) (authenticatedRotation, error) {
	var result authenticatedRotation
	public, previous, err := authenticateInstallationHistory(prior)
	if err != nil {
		return result, err
	}
	var envelope Envelope
	if err := strictJSON(rotation, MaxRotationBytes, &envelope); err != nil {
		return result, err
	}
	if envelope.SchemaVersion != 1 || envelope.KeyID != previous.KeyID {
		return result, errors.New("rotation does not match the enrolled key")
	}
	payload, err := canonicalBase64(envelope.Payload, 1, MaxRotationPayloadBytes)
	if err != nil {
		return result, errors.New("invalid rotation payload encoding or size")
	}
	signature, err := canonicalBase64(envelope.Signature, ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(public, append([]byte(rotationDomain), payload...), signature) {
		return result, errors.New("rotation signature verification failed")
	}
	var request rotationRequest
	if err := strictJSON(payload, MaxRotationPayloadBytes, &request); err != nil {
		return result, err
	}
	if request.SchemaVersion != 1 || request.PreviousKeyID != previous.KeyID || request.PreviousRevision != previous.Policy.Revision || request.PreviousPayloadSHA256 != previous.PayloadSHA256 {
		return result, errors.New("rotation does not bind the current enrolled policy state")
	}
	nextPublic, err := PublicKey(request.NextPublicKey)
	if err != nil {
		return result, err
	}
	if bytes.Equal(public, nextPublic) {
		return result, errors.New("rotation must change the signing key")
	}
	nextEnvelope, err := json.Marshal(request.NextEnvelope)
	if err != nil {
		return result, err
	}
	next, err := Verify(nextEnvelope, nextPublic, now, previous.Policy.Revision)
	if err != nil {
		return result, err
	}
	return authenticatedRotation{RotationReview{previous.KeyID, previous.Policy.Revision, previous.PayloadSHA256, next, true, false}, nextPublic, nextEnvelope}, nil
}

func rotationTransition(prior, rotation []byte, now time.Time) ([]byte, InstallResult, error) {
	checked, err := verifyRotation(prior, rotation, now)
	if err != nil {
		return nil, InstallResult{}, err
	}
	review := checked.review
	// Carry the authenticated material directly into installation preparation.
	candidate, err := PrepareInstallation(checked.nextEnvelope, checked.nextPublic, now, review.PreviousRevision)
	if err != nil {
		return nil, InstallResult{}, err
	}
	result := InstallResult{Operation: "rotate", PreviousKeyID: review.PreviousKeyID, PreviousRevision: review.PreviousRevision, Revision: review.Next.Policy.Revision, KeyID: review.Next.KeyID, PayloadSHA256: review.Next.PayloadSHA256, Enforcement: "partial"}
	return candidate, result, nil
}

// Rotate changes the fixed native policy source through the same protected
// transaction and revision reservation used by ordinary policy updates.
func Rotate(rotation []byte) (InstallResult, error) {
	if len(rotation) == 0 || len(rotation) > MaxRotationBytes {
		return InstallResult{}, errors.New("managed rotation exceeds size limit or is empty")
	}
	return applyMachinePolicy(rotation, nil, changeRotate)
}
