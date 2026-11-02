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

func TestMachineSnapshotRequiresAcceptedVersionTwo(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	source, record, err := prepareNativeAcceptance(prior, now)
	if err != nil {
		t.Fatal(err)
	}
	valid := machineSnapshot{source: source, acceptance: record, present: true, acceptancePresent: true}
	authority, accepted, err := decodeMachineSnapshot(valid, now)
	if err != nil || authority.verified.Policy.Revision != 2 || accepted.revision != 2 {
		t.Fatal("valid paired policy unavailable", err)
	}
	legacy, history, err := decodeMachineSnapshot(machineSnapshot{source: prior, present: true}, now)
	if err != nil || legacy == nil || history != nil {
		t.Fatal("legacy compatibility changed", err)
	}
	for _, bad := range []machineSnapshot{
		{source: source, present: true},
		{source: source, present: true, acceptancePresent: true},
		{source: source, present: true, acceptance: []byte("{}"), acceptancePresent: true},
		{source: prior, present: true, acceptance: record, acceptancePresent: true},
		{source: nil, present: true, acceptance: record, acceptancePresent: true},
		{source: source, present: false},
		{acceptance: record, acceptancePresent: true},
	} {
		if _, _, err := decodeMachineSnapshot(bad, now); err == nil {
			t.Fatal("inconsistent policy state authorized")
		}
	}
	if _, _, err := decodeMachineSnapshot(valid, now.Add(2*time.Hour)); err == nil {
		t.Fatal("accepted history reauthorized expired permissions")
	}
	updated, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	newerSource, newerRecord, err := prepareNativeAcceptance(updated, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeMachineSnapshot(machineSnapshot{source: source, acceptance: newerRecord, present: true, acceptancePresent: true}, now); !errors.Is(err, ErrUnavailable) {
		t.Fatal("primary rollback ignored accepted state", err)
	}
	if _, _, err := decodeMachineSnapshot(machineSnapshot{source: newerSource, acceptance: record, present: true, acceptancePresent: true}, now); !errors.Is(err, ErrUnavailable) {
		t.Fatal("new primary paired with old record", err)
	}
}

func TestTransactionAcceptanceBlocksStaleOrMissingHistory(t *testing.T) {
	prior, next, public, _, now := renewalFixture(t)
	source, record, err := prepareNativeAcceptance(prior, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tx := range []*fakeInstallationTransaction{
		{prior: source, present: true},
		{prior: source, present: true, acceptance: []byte("{}"), acceptancePresent: true},
		{prior: prior, present: true, acceptance: record, acceptancePresent: true},
	} {
		result, err := commitInstallation(tx, next, public, changeUpdate, func() time.Time { return now })
		if err == nil || result.Committed || tx.stageCalls != 0 || tx.commitCalls != 0 {
			t.Fatal("unbound policy state updated", result, err)
		}
	}
	good := &fakeInstallationTransaction{prior: source, present: true, acceptance: record, acceptancePresent: true}
	result, err := commitInstallation(good, next, nil, changeUpdate, func() time.Time { return now })
	if err != nil || !result.Committed {
		t.Fatal("bound forward update failed", result, err)
	}
	history, err := readAcceptance(good.publishedAcceptance)
	if err != nil || history.revision != 3 || history.checkSource(good.published) != nil {
		t.Fatal("publication lost accepted state", err)
	}
}

func TestRecoveryCannotResetAcceptedFloorAfterCorruption(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	latest, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	_, record, err := prepareNativeAcceptance(latest, now)
	if err != nil {
		t.Fatal(err)
	}
	stale, public, _, _ := recoveryFixture(t, nil, time.Hour)
	denied := &fakeInstallationTransaction{present: true, acceptance: record, acceptancePresent: true}
	result, err := commitRecovery(denied, stale, public, 2, func() time.Time { return now })
	if !errors.Is(err, ErrDenied) || result.Committed || denied.stageCalls != 0 || denied.commitCalls != 0 {
		t.Fatal("stale recovery reset accepted revision", result, err)
	}
	freshPublic, freshPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(Policy{SchemaVersion: 1, Revision: 4, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(payload, freshPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := SignRecovery(nil, envelope, freshPrivate, 2, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	allowed := &fakeInstallationTransaction{present: true, acceptance: record, acceptancePresent: true}
	result, err = commitRecovery(allowed, approval, freshPublic, 2, func() time.Time { return now })
	if err != nil || !result.Committed || result.Revision != 4 || result.PreviousRevision != 3 {
		t.Fatal("higher approved repair failed", result, err)
	}
	history, err := readAcceptance(allowed.publishedAcceptance)
	if err != nil || history.revision != 4 || history.keyID != KeyID(freshPublic) || history.checkSource(allowed.published) != nil {
		t.Fatal("repair failed to advance the accepted state", err)
	}
	if bytes.Equal(allowed.publishedAcceptance, record) {
		t.Fatal("repair retained stale counter")
	}
}
