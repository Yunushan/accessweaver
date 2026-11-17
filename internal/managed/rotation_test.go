package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type rotationFixtureData struct {
	prior, next, rotation  []byte
	oldPublic, newPublic   ed25519.PublicKey
	oldPrivate, newPrivate ed25519.PrivateKey
	now                    time.Time
}

func rotationFixture(t *testing.T) rotationFixtureData {
	t.Helper()
	prior, _, public, private, now := renewalFixture(t)
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{SchemaVersion: 1, Revision: 3, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), AllowDiagnostics: true}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Sign(payload, nextPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := SignRotation(prior, next, nextPublic, private, now)
	if err != nil {
		t.Fatal(err)
	}
	return rotationFixtureData{prior, next, rotation, public, nextPublic, private, nextPrivate, now}
}
func signedRotationMutation(t *testing.T, f rotationFixtureData, change func([]byte) []byte) []byte {
	t.Helper()
	var envelope Envelope
	if err := json.Unmarshal(f.rotation, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalBase64(envelope.Payload, 1, MaxRotationPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload = change(payload)
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.oldPrivate, append([]byte(rotationDomain), payload...)))
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func mutateRotationRequest(t *testing.T, f rotationFixtureData, change func(*rotationRequest)) []byte {
	t.Helper()
	return signedRotationMutation(t, f, func(payload []byte) []byte {
		var request rotationRequest
		if err := json.Unmarshal(payload, &request); err != nil {
			t.Fatal(err)
		}
		change(&request)
		data, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		return data
	})
}
func TestRotationAuthenticatesBothKeysAndPreservesRevisionHistory(t *testing.T) {
	f := rotationFixture(t)
	review, err := VerifyRotation(f.prior, f.rotation, f.oldPublic, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if review.PreviousKeyID != KeyID(f.oldPublic) || review.PreviousRevision != 2 || review.Next.KeyID != KeyID(f.newPublic) || review.Next.Policy.Revision != 3 || !review.SignatureValid || review.RuntimeEnforced || review.Next.RuntimeEnforced {
		t.Fatal("misleading rotation review", review)
	}
	candidate, result, err := rotationTransition(f.prior, f.rotation, f.now)
	if err != nil || result.Operation != "rotate" || result.PreviousKeyID != KeyID(f.oldPublic) || result.KeyID != KeyID(f.newPublic) || result.Committed {
		t.Fatal(result, err)
	}
	installed, err := parseInstallation(candidate)
	if err != nil || installed.MinimumRevision != 2 {
		t.Fatal("rotation reset the floor", err)
	}
	authority, err := DecodeInstallation(candidate, f.now)
	if err != nil || authority.verified.KeyID != KeyID(f.newPublic) || !authority.verified.Policy.AllowDiagnostics {
		t.Fatal("new signed policy lost", err)
	}
	if _, _, err := rotationTransition(candidate, f.rotation, f.now); err == nil {
		t.Fatal("rotation replay accepted")
	}
	policy := Policy{SchemaVersion: 1, Revision: 4, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}
	payload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	oldSigned, err := Sign(payload, f.oldPrivate, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installationTransition(candidate, oldSigned, nil, false, f.now); err == nil {
		t.Fatal("retired key authorized update")
	}
	newSigned, err := Sign(payload, f.newPrivate, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, result, err := installationTransition(candidate, newSigned, nil, false, f.now); err != nil || result.Revision != 4 {
		t.Fatal("new key could not update", result, err)
	}
	for _, private := range []ed25519.PrivateKey{f.oldPrivate, f.newPrivate} {
		if bytes.Contains(f.rotation, []byte(base64.StdEncoding.EncodeToString(private))) {
			t.Fatal("rotation exported private key")
		}
	}
}
func TestRotationRequiresPinnedPriorStateAndActualKeyChange(t *testing.T) {
	f := rotationFixture(t)
	for _, key := range []ed25519.PublicKey{nil, f.newPublic} {
		if _, err := VerifyRotation(f.prior, f.rotation, key, f.now); err == nil {
			t.Fatal("review trusted key selected by prior file")
		}
	}
	// A different valid policy at the same revision is also a different state.
	var previous Installation
	if err := json.Unmarshal(f.prior, &previous); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalBase64(previous.Envelope.Payload, 1, MaxPolicyBytes)
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	p.AllowDownloads = true
	payload, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	forkEnvelope, err := Sign(payload, f.oldPrivate, f.now)
	if err != nil {
		t.Fatal(err)
	}
	fork, err := PrepareInstallation(forkEnvelope, f.oldPublic, f.now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rotationTransition(fork, f.rotation, f.now); err == nil {
		t.Fatal("rotation accepted different policy contents at the same revision")
	}
	if _, err := SignRotation(f.prior, f.next, f.newPublic, f.newPrivate, f.now); err == nil {
		t.Fatal("new key authorized its own enrollment")
	}
	for _, private := range []ed25519.PrivateKey{nil, append(append(ed25519.PrivateKey(nil), f.oldPrivate[:32]...), f.newPublic...)} {
		if _, err := SignRotation(f.prior, f.next, f.newPublic, private, f.now); err == nil {
			t.Fatal("invalid rotation private key accepted")
		}
	}
	for _, public := range []ed25519.PublicKey{nil, f.oldPublic} {
		if _, err := SignRotation(f.prior, f.next, public, f.oldPrivate, f.now); err == nil {
			t.Fatal("unchanged/invalid new key accepted")
		}
	}
}
func TestRotationRejectsAuthenticatedMalformedAndStaleTransitions(t *testing.T) {
	f := rotationFixture(t)
	for name, change := range map[string]func(*rotationRequest){
		"schema":           func(r *rotationRequest) { r.SchemaVersion = 2 },
		"prior-key":        func(r *rotationRequest) { r.PreviousKeyID = KeyID(f.newPublic) },
		"prior-revision":   func(r *rotationRequest) { r.PreviousRevision = 1 },
		"prior-payload":    func(r *rotationRequest) { r.PreviousPayloadSHA256 = strings.Repeat("0", 64) },
		"new-key":          func(r *rotationRequest) { r.NextPublicKey = base64.StdEncoding.EncodeToString(f.oldPublic) },
		"new-key-encoding": func(r *rotationRequest) { r.NextPublicKey = "invalid" },
		"new-signature": func(r *rotationRequest) {
			r.NextEnvelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
		},
		"new-envelope-key": func(r *rotationRequest) { r.NextEnvelope.KeyID = KeyID(f.oldPublic) },
	} {
		t.Run(name, func(t *testing.T) {
			data := mutateRotationRequest(t, f, change)
			if _, _, err := rotationTransition(f.prior, data, f.now); err == nil {
				t.Fatal("invalid signed transition accepted")
			}
		})
	}
	for _, change := range []func([]byte) []byte{
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"previousRevision":2`), []byte(`"previousRevision":2,"previousRevision":2`), 1)
		},
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"previousKeyId":`), []byte(`"PreviousKeyId":`), 1)
		},
		func(b []byte) []byte { return append(b[:len(b)-1], []byte(`,"unknown":true}`)...) },
	} {
		data := signedRotationMutation(t, f, change)
		if _, _, err := rotationTransition(f.prior, data, f.now); err == nil {
			t.Fatal("ambiguous/unknown signed rotation field accepted")
		}
	}
	for _, invalid := range [][]byte{[]byte(`null`), []byte(`{}`), bytes.Repeat([]byte(" "), MaxRotationBytes+1), bytes.Replace(f.rotation, []byte(`"schemaVersion": 1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)} {
		if _, _, err := rotationTransition(f.prior, invalid, f.now); err == nil {
			t.Fatal("invalid outer envelope accepted")
		}
	}
}
func TestRotationDomainSeparatesSignaturesAndRejectsTampering(t *testing.T) {
	f := rotationFixture(t)
	var envelope Envelope
	if err := json.Unmarshal(f.rotation, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalBase64(envelope.Payload, 1, MaxRotationPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range [][]byte{payload, append([]byte(signatureDomain), payload...)} {
		envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.oldPrivate, message))
		invalid, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := rotationTransition(f.prior, invalid, f.now); err == nil {
			t.Fatal("signature from a different protocol accepted")
		}
	}
	if _, err := Verify(f.rotation, f.oldPublic, f.now, 0); err == nil {
		t.Fatal("rotation accepted as policy envelope")
	}
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.oldPrivate, append([]byte(rotationDomain), payload...)))
	envelope.Payload = base64.StdEncoding.EncodeToString(append(payload, ' '))
	invalid, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rotationTransition(f.prior, invalid, f.now); err == nil {
		t.Fatal("signed payload byte tampering accepted")
	}
}
func TestExpiredPriorCanRotateButExpiredNextCannot(t *testing.T) {
	f := rotationFixture(t)
	later := f.now.Add(2 * time.Hour)
	if _, err := DecodeInstallation(f.prior, later); err == nil {
		t.Fatal("expired prior authorized runtime")
	}
	if _, _, err := rotationTransition(f.prior, f.rotation, later); err == nil {
		t.Fatal("expired replacement policy accepted")
	}
	p := Policy{SchemaVersion: 1, Revision: 3, IssuedAt: later.Add(-time.Minute), ExpiresAt: later.Add(time.Hour)}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Sign(payload, f.newPrivate, later)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := SignRotation(f.prior, next, f.newPublic, f.oldPrivate, later)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rotationTransition(f.prior, rotation, later); err != nil {
		t.Fatal("expired enrolled key could not rotate", err)
	}
	if _, err := DecodeInstallation(f.prior, later); err == nil {
		t.Fatal("historical rotation check revived expired permission")
	}
}
func TestRotationTransactionFailureNeverPublishesReplacement(t *testing.T) {
	f := rotationFixture(t)
	failure := errors.New("injected rotation failure")
	for _, fault := range []string{"invalid", "read", "stage", "commit", "expiry", "no-enrollment"} {
		t.Run(fault, func(t *testing.T) {
			tx := &fakeInstallationTransaction{prior: f.prior, present: true}
			rotation := f.rotation
			switch fault {
			case "invalid":
				rotation = []byte(`{}`)
			case "read":
				tx.readErr = failure
			case "stage":
				tx.stageErr = failure
			case "commit":
				tx.commitErr = failure
			case "no-enrollment":
				tx.present = false
				tx.prior = nil
			}
			calls := 0
			clock := func() time.Time {
				calls++
				if fault == "expiry" && calls > 1 {
					return f.now.Add(2 * time.Hour)
				}
				return f.now
			}
			result, err := commitInstallation(tx, rotation, nil, changeRotate, clock)
			if err == nil || result.Committed || tx.published != nil || tx.closeCalls != 1 {
				t.Fatal("failed rotation published replacement", result, err)
			}
		})
	}
	tx := &fakeInstallationTransaction{prior: f.prior, present: true}
	result, err := commitInstallation(tx, f.rotation, nil, changeRotate, func() time.Time { return f.now })
	if err != nil || !result.Committed || result.PreviousRevision != 2 || result.Revision != 3 || result.PreviousKeyID != KeyID(f.oldPublic) || result.KeyID != KeyID(f.newPublic) {
		t.Fatal("valid rotation failed", result, err)
	}
}
func FuzzVerifyRotation(f *testing.F) {
	fixture := deterministicFuzzRotation(f)
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schemaVersion":1}`))
	f.Add(fixture.rotation)
	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		review, err := VerifyRotation(fixture.prior, data, fixture.oldPublic, fixture.now)
		if !bytes.Equal(before, data) {
			t.Fatal("rotation verification changed input bytes")
		}
		if err == nil {
			assertFuzzRotation(t, fixture, data, review)
		} else if review.SignatureValid || review.RuntimeEnforced {
			t.Fatal("rejected rotation returned usable review")
		}
	})
}

func TestAuthorizedRotationCannotResetRevisionOrIgnoreReplacementValidity(t *testing.T) {
	f := rotationFixture(t)
	for _, kind := range []string{"older", "same", "future", "expired"} {
		t.Run(kind, func(t *testing.T) {
			p := Policy{SchemaVersion: 1, Revision: 3, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}
			signingTime := f.now
			switch kind {
			case "older":
				p.Revision = 1
			case "same":
				p.Revision = 2
			case "future":
				p.IssuedAt = f.now.Add(10 * time.Minute)
				p.ExpiresAt = f.now.Add(2 * time.Hour)
				signingTime = p.IssuedAt
			case "expired":
				p.IssuedAt = f.now.Add(-2 * time.Hour)
				p.ExpiresAt = f.now.Add(-time.Hour)
				signingTime = f.now.Add(-90 * time.Minute)
			}
			payload, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			next, err := Sign(payload, f.newPrivate, signingTime)
			if err != nil {
				t.Fatal(err)
			}
			invalid := mutateRotationRequest(t, f, func(r *rotationRequest) {
				if err := json.Unmarshal(next, &r.NextEnvelope); err != nil {
					t.Fatal(err)
				}
			})
			if _, _, err := rotationTransition(f.prior, invalid, f.now); err == nil {
				t.Fatal("old-key authorization bypassed replacement policy requirements")
			}
			if _, err := SignRotation(f.prior, next, f.newPublic, f.oldPrivate, f.now); err == nil {
				t.Fatal("offline signer approved an unusable replacement")
			}
		})
	}
}
