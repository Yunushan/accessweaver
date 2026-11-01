package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func renewalFixture(t *testing.T) ([]byte, []byte, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	payload, public, private, now := fixture(t)
	signed, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := PrepareInstallation(signed, public, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	var policy Policy
	if err := json.Unmarshal(payload, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Revision = 3
	policy.AllowProfileChanges = true
	payload, err = json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	return prior, next, public, private, now
}

func TestPolicyUpdateDerivesTrustAndFloorFromPriorEnrollment(t *testing.T) {
	prior, next, public, _, now := renewalFixture(t)
	candidate, result, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation != "update" || result.PreviousRevision != 2 || result.Revision != 3 || result.Committed || result.KeyID != KeyID(public) || result.Enforcement != "partial" {
		t.Fatalf("incorrect update review: %+v", result)
	}
	installed, err := parseInstallation(candidate)
	if err != nil || installed.MinimumRevision != 2 {
		t.Fatal("accepted revision not retained as floor", err)
	}
	authority, err := DecodeInstallation(candidate, now)
	if err != nil || !authority.verified.Policy.AllowProfileChanges {
		t.Fatal("candidate lost signed permissions", err)
	}
	if _, _, err := installationTransition(candidate, next, nil, false, now); err == nil {
		t.Fatal("same revision replay accepted")
	}
	old, err := parseInstallation(prior)
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope, err := json.Marshal(old.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installationTransition(candidate, oldEnvelope, nil, false, now); err == nil {
		t.Fatal("older signed revision accepted")
	}
}

func TestExpiredPolicyCanRenewWithoutAuthorizingOldPermissions(t *testing.T) {
	prior, _, public, private, now := renewalFixture(t)
	later := now.Add(2 * time.Hour)
	if _, err := DecodeInstallation(prior, later); err == nil {
		t.Fatal("expired policy authorized runtime")
	}
	policy := Policy{SchemaVersion: 1, Revision: 3, IssuedAt: later.Add(-time.Minute), ExpiresAt: later.Add(time.Hour)}
	payload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Sign(payload, private, later)
	if err != nil {
		t.Fatal(err)
	}
	candidate, result, err := installationTransition(prior, next, nil, false, later)
	if err != nil || result.PreviousRevision != 2 || result.KeyID != KeyID(public) {
		t.Fatal("expired enrollment could not renew", err)
	}
	if _, err := DecodeInstallation(candidate, later); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstallation(prior, later); err == nil {
		t.Fatal("historical authentication enabled old policy")
	}
}

func TestPolicyUpdateRejectsTrustSubstitutionAndInvalidPriorState(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	other, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var envelope Envelope
	if err := json.Unmarshal(next, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalBase64(envelope.Payload, 1, MaxPolicyBytes)
	if err != nil {
		t.Fatal(err)
	}
	otherEnvelope, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installationTransition(prior, otherEnvelope, other, false, now); err == nil {
		t.Fatal("caller-selected replacement key accepted")
	}
	for _, invalid := range [][]byte{
		[]byte(`{}`),
		bytes.Replace(prior, []byte(`"minimumRevision": 1`), []byte(`"minimumRevision": 2`), 1),
		bytes.Replace(prior, []byte(`"minimumRevision": 1,`), nil, 1),
		bytes.Repeat([]byte(" "), MaxInstallationBytes+1),
	} {
		if _, _, err := installationTransition(invalid, next, nil, false, now); err == nil {
			t.Fatal("invalid prior trust accepted")
		}
	}
	installed, err := parseInstallation(prior)
	if err != nil {
		t.Fatal(err)
	}
	installed.Envelope.Signature = envelope.Signature
	tampered, err := json.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := installationTransition(tampered, next, nil, false, now); err == nil {
		t.Fatal("unauthenticated prior revision used")
	}
}

type fakeInstallationTransaction struct {
	prior, staged, published               []byte
	present                                bool
	readErr, stageErr, commitErr, closeErr error
	stageCalls, commitCalls, closeCalls    int
}

func (tx *fakeInstallationTransaction) Read() ([]byte, bool, error) {
	return tx.prior, tx.present, tx.readErr
}
func (tx *fakeInstallationTransaction) Stage(data []byte) error {
	tx.stageCalls++
	tx.staged = append([]byte(nil), data...)
	return tx.stageErr
}
func (tx *fakeInstallationTransaction) Commit() error {
	tx.commitCalls++
	if tx.commitErr == nil {
		tx.published = append([]byte(nil), tx.staged...)
	}
	return tx.commitErr
}
func (tx *fakeInstallationTransaction) Close() error { tx.closeCalls++; return tx.closeErr }

func TestPolicyTransactionFailureDoesNotPublishCandidate(t *testing.T) {
	prior, next, public, _, now := renewalFixture(t)
	failure := errors.New("injected transaction failure")
	for _, fault := range []string{"read", "stage", "commit", "existing-install", "absent-update", "invalid-candidate", "expired-after-stage"} {
		t.Run(fault, func(t *testing.T) {
			tx := &fakeInstallationTransaction{prior: prior, present: true}
			initial := false
			input := next
			clockCalls := 0
			clock := func() time.Time {
				clockCalls++
				if fault == "expired-after-stage" && clockCalls > 1 {
					return now.Add(2 * time.Hour)
				}
				return now
			}
			switch fault {
			case "read":
				tx.readErr = failure
			case "stage":
				tx.stageErr = failure
			case "commit":
				tx.commitErr = failure
			case "existing-install":
				initial = true
				input = prior
			case "absent-update":
				tx.present = false
				tx.prior = nil
			case "invalid-candidate":
				input = []byte(`{}`)
			}
			result, err := commitInstallation(tx, input, public, initial, clock)
			if err == nil || result.Committed || tx.closeCalls != 1 || tx.published != nil {
				t.Fatalf("failed update published state: %+v %v", result, err)
			}
			if fault != "commit" && tx.commitCalls != 0 {
				t.Fatal("commit attempted after validation/stage failure")
			}
		})
	}
}

func TestInitialPolicyInstallRequiresIndependentPinAndAbsentSource(t *testing.T) {
	prior, _, public, _, now := renewalFixture(t)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []ed25519.PublicKey{nil, other} {
		if _, _, err := installationTransition(nil, prior, key, true, now); err == nil {
			t.Fatal("untrusted bootstrap key accepted")
		}
	}
	tx := &fakeInstallationTransaction{}
	result, err := commitInstallation(tx, prior, public, true, func() time.Time { return now })
	if err != nil || !result.Committed || result.Revision != 2 || result.PreviousRevision != 0 || tx.closeCalls != 1 || tx.commitCalls != 1 {
		t.Fatal("valid initial install did not commit", result, err)
	}
	if !bytes.Equal(tx.published, prior) {
		t.Fatal("initial install changed reviewed document")
	}
}

func TestPolicyCommitIsReportedWhenHandleCleanupFails(t *testing.T) {
	prior, next, public, _, now := renewalFixture(t)
	cleanupFailure := errors.New("injected handle close failure")
	tx := &fakeInstallationTransaction{prior: prior, present: true, closeErr: cleanupFailure}
	result, err := commitInstallation(tx, next, public, false, func() time.Time { return now })
	if !errors.Is(err, cleanupFailure) || !result.Committed || tx.published == nil || tx.closeCalls != 1 {
		t.Fatal("post-commit cleanup failure concealed the committed outcome", result, err)
	}
}
