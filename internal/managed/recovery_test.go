package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func recoveryFixture(t *testing.T, prior []byte, lifetime time.Duration) ([]byte, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	_, next, public, private, now := renewalFixture(t)
	data, err := SignRecovery(prior, next, private, 2, now, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	return data, public, private, now
}
func TestRecoveryBindsDamagedSourceIndependentKeyAndFloor(t *testing.T) {
	prior := []byte("damaged machine policy\n")
	data, public, _, now := recoveryFixture(t, prior, time.Hour)
	review, candidate, err := recoveryTransition(prior, data, public, 2, now)
	if err != nil || !review.SignatureValid || review.RuntimeEnforced || review.PreviousAuthenticated || review.PreviousRevision != 0 || review.MinimumRevision != 2 || review.Next.Policy.Revision != 3 || review.Next.KeyID != KeyID(public) {
		t.Fatal(review, err)
	}
	if _, err := DecodeInstallation(prior, now); err == nil {
		t.Fatal("damaged source acquired authority")
	}
	a, err := DecodeInstallation(candidate, now)
	if err != nil || a.verified.Policy.Revision != 3 {
		t.Fatal("repaired policy did not verify", err)
	}
	if _, err := VerifyRecovery(candidate, data, public, 2, now); err == nil {
		t.Fatal("recovery replay matched repaired source")
	}
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		prior   []byte
		key     ed25519.PublicKey
		minimum uint64
		at      time.Time
	}{
		{"different source", append(bytes.Clone(prior), ' '), public, 2, now},
		{"wrong pin", prior, wrong, 2, now},
		{"no pin", prior, nil, 2, now},
		{"wrong floor", prior, public, 1, now},
		{"no floor", prior, public, 0, now},
		{"unsafe floor", prior, public, maxSafeRevision, now},
		{"expired", prior, public, 2, now.Add(time.Hour)},
		{"not issued", prior, public, 2, now.Add(-time.Nanosecond)},
		{"zero time", prior, public, 2, time.Time{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := VerifyRecovery(tt.prior, data, tt.key, tt.minimum, tt.at); err == nil {
				t.Fatal("unapproved recovery accepted")
			}
		})
	}
}
func TestRecoveryCannotRollBackAuthenticatedHistory(t *testing.T) {
	prior, next, public, private, now := renewalFixture(t)
	data, err := SignRecovery(prior, next, private, 1, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	review, candidate, err := recoveryTransition(prior, data, public, 1, now)
	if err != nil || !review.PreviousAuthenticated || review.PreviousRevision != 2 {
		t.Fatal(review, err)
	}
	installed, err := parseInstallation(candidate)
	if err != nil || installed.MinimumRevision != 2 {
		t.Fatal("authenticated revision floor lost", installed, err)
	}
	var p Policy
	p = review.Next.Policy
	p.Revision = 2
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	old, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRecovery(prior, old, private, 1, now, time.Hour); err == nil {
		t.Fatal("rollback to existing revision accepted")
	}
	// Expired prior permissions remain unusable, while authentic history still
	// raises the independent recovery floor.
	later := now.Add(2 * time.Hour)
	p.Revision = 3
	p.IssuedAt = later.Add(-time.Minute)
	p.ExpiresAt = later.Add(time.Hour)
	payload, _ = json.Marshal(p)
	renewed, err := Sign(payload, private, later)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignRecovery(prior, renewed, private, 1, later, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if review, err := VerifyRecovery(prior, signed, public, 1, later); err != nil || review.PreviousRevision != 2 {
		t.Fatal(review, err)
	}
	if _, err := DecodeInstallation(prior, later); err == nil {
		t.Fatal("historical authentication made expired permissions usable")
	}
}
func mutateSignedRecovery(t *testing.T, data []byte, private ed25519.PrivateKey, mutate func([]byte) []byte) []byte {
	t.Helper()
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload = mutate(payload)
	e.Payload = base64.StdEncoding.EncodeToString(payload)
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(recoveryDomain), payload...)))
	result, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestRecoveryStrictParsingAndSignatureDomains(t *testing.T) {
	prior := []byte("invalid source")
	data, public, private, now := recoveryFixture(t, prior, time.Hour)
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown field": func(p []byte) []byte { return append([]byte(`{"unknown":true,`), p[1:]...) },
		"duplicate":     func(p []byte) []byte { return append([]byte(`{"schemaVersion":1,`), p[1:]...) },
		"case alias":    func(p []byte) []byte { return bytes.Replace(p, []byte(`"issuedAt"`), []byte(`"IssuedAt"`), 1) },
		"missing floor": func(p []byte) []byte { return bytes.Replace(p, []byte(`"minimumRevision":2,`), nil, 1) },
		"null floor": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"minimumRevision":2`), []byte(`"minimumRevision":null`), 1)
		},
		"unsafe floor": func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"minimumRevision":2`), []byte(`"minimumRevision":9007199254740991`), 1)
		},
		"bad source hash": func(p []byte) []byte {
			var r recoveryRequest
			_ = json.Unmarshal(p, &r)
			r.PreviousSourceSHA256 = "A" + r.PreviousSourceSHA256[1:]
			b, _ := json.Marshal(r)
			return b
		},
		"too long": func(p []byte) []byte {
			var r recoveryRequest
			_ = json.Unmarshal(p, &r)
			r.ExpiresAt = r.IssuedAt.Add(25 * time.Hour)
			b, _ := json.Marshal(r)
			return b
		},
		"no expiry": func(p []byte) []byte {
			var r recoveryRequest
			_ = json.Unmarshal(p, &r)
			r.ExpiresAt = time.Time{}
			b, _ := json.Marshal(r)
			return b
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := mutateSignedRecovery(t, data, private, mutate)
			if _, err := VerifyRecovery(prior, bad, public, 2, now); err == nil {
				t.Fatal("invalid signed recovery accepted")
			}
		})
	}
	var e Envelope
	_ = json.Unmarshal(data, &e)
	payload, _ := base64.StdEncoding.DecodeString(e.Payload)
	for _, domain := range []string{signatureDomain, rotationDomain, ""} {
		e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(domain), payload...)))
		bad, _ := json.Marshal(e)
		if _, err := VerifyRecovery(prior, bad, public, 2, now); err == nil {
			t.Fatal("cross-protocol signature accepted")
		}
	}
	for _, bad := range [][]byte{nil, []byte(`{}`), append(bytes.Clone(data), []byte(`{}`)...), bytes.Repeat([]byte(" "), MaxRecoveryBytes+1), bytes.Replace(data, []byte(`"signature"`), []byte(`"Signature"`), 1)} {
		if _, err := VerifyRecovery(prior, bad, public, 2, now); err == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
	for _, badPrior := range [][]byte{nil, bytes.Repeat([]byte("x"), MaxInstallationBytes+1)} {
		if _, err := VerifyRecovery(badPrior, data, public, 2, now); err == nil {
			t.Fatal("unbounded source accepted")
		}
	}
	for _, life := range []time.Duration{0, -time.Second, 25 * time.Hour} {
		_, next, _, key, now := renewalFixture(t)
		if _, err := SignRecovery(prior, next, key, 2, now, life); err == nil {
			t.Fatal("invalid lifetime signed")
		}
	}
}
func TestRecoveryTransactionRetainsPriorOnFailureAndRechecksApproval(t *testing.T) {
	prior := []byte("damaged source")
	data, public, _, now := recoveryFixture(t, prior, time.Second)
	failure := errors.New("injected recovery transaction failure")
	for _, fault := range []string{"read", "absent", "stage", "commit", "expired-after-stage", "different-source"} {
		t.Run(fault, func(t *testing.T) {
			tx := &fakeInstallationTransaction{prior: prior, present: true}
			calls := 0
			clock := func() time.Time {
				calls++
				if fault == "expired-after-stage" && calls > 1 {
					return now.Add(time.Second)
				}
				return now
			}
			switch fault {
			case "read":
				tx.readErr = failure
			case "absent":
				tx.present = false
			case "stage":
				tx.stageErr = failure
			case "commit":
				tx.commitErr = failure
			case "different-source":
				tx.prior = []byte("different")
			}
			result, err := commitRecovery(tx, data, public, 2, clock)
			if err == nil || result.Committed || tx.published != nil || tx.closeCalls != 1 {
				t.Fatalf("failed recovery published: %+v %v", result, err)
			}
			if fault != "commit" && tx.commitCalls != 0 {
				t.Fatal("commit attempted after failed checks")
			}
		})
	}
	for _, closeFailure := range []bool{false, true} {
		tx := &fakeInstallationTransaction{prior: prior, present: true}
		if closeFailure {
			tx.closeErr = failure
		}
		result, err := commitRecovery(tx, data, public, 2, func() time.Time { return now })
		if result.Operation != "recover" || !result.Committed || result.Revision != 3 || result.PreviousSourceSHA256 == "" || result.RecoveryPayloadSHA256 == "" || tx.published == nil || tx.closeCalls != 1 || errors.Is(err, failure) != closeFailure {
			t.Fatal("recovery outcome concealed", result, err)
		}
	}
}

func TestRecoveryTransactionRejectsReplacementExpiryAfterStage(t *testing.T) {
	_, next, public, private, now := renewalFixture(t)
	prior := []byte("damaged source")
	data, err := SignRecovery(prior, next, private, 2, now, 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tx := &fakeInstallationTransaction{prior: prior, present: true}
	calls := 0
	result, err := commitRecovery(tx, data, public, 2, func() time.Time {
		calls++
		if calls > 1 {
			return now.Add(2 * time.Hour)
		}
		return now
	})
	if err == nil || result.Committed || tx.commitCalls != 0 || tx.published != nil || tx.closeCalls != 1 {
		t.Fatal("expired replacement committed under a still-valid recovery approval", result, err)
	}
}
func TestRecoverySigningRejectsInvalidKeyAndUnapprovedReplacement(t *testing.T) {
	_, next, _, private, now := renewalFixture(t)
	prior := []byte("damaged source")
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []ed25519.PrivateKey{nil, private[:32], otherPrivate, append(bytes.Clone(private[:63]), private[63]^1)} {
		if _, err := SignRecovery(prior, next, key, 2, now, time.Hour); err == nil {
			t.Fatal("invalid key or different replacement signer accepted")
		}
	}
	for _, floor := range []uint64{0, 3, maxSafeRevision} {
		if _, err := SignRecovery(prior, next, private, floor, now, time.Hour); err == nil {
			t.Fatal("unsafe/stale replacement floor accepted")
		}
	}
}
func FuzzSignedRecoveryPayload(f *testing.F) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	prior := []byte("damaged source")
	p := Policy{SchemaVersion: 1, Revision: 2, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload, err := json.Marshal(p)
	if err != nil {
		f.Fatal(err)
	}
	next, err := Sign(payload, private, now)
	if err != nil {
		f.Fatal(err)
	}
	recovery, err := SignRecovery(prior, next, private, 1, now, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	var envelope Envelope
	if err := json.Unmarshal(recovery, &envelope); err != nil {
		f.Fatal(err)
	}
	original, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(original)
	f.Add([]byte(`{}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > maxRecoveryPayloadBytes {
			return
		}
		envelope := Envelope{1, KeyID(public), base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(recoveryDomain), payload...)))}
		data, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		review, candidate, err := recoveryTransition(prior, data, public, 1, now)
		if err == nil {
			a, err := DecodeInstallation(candidate, now)
			if err != nil || !review.SignatureValid || review.RuntimeEnforced || review.MinimumRevision != 1 || a.verified.Policy.Revision <= 1 || a.verified.KeyID != KeyID(public) {
				t.Fatalf("invalid accepted recovery: %+v %v", review, err)
			}
		}
	})
}
