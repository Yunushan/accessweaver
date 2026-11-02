package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAcceptancePreservesExactAuthenticatedHistory(t *testing.T) {
	prior, _, public, _, now := renewalFixture(t)
	source := append([]byte(" \n"), prior...)
	source = append(source, []byte("\t\r\n")...)
	original := bytes.Clone(source)
	record, err := prepareAcceptance(source, now)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := readAcceptance(record)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(source)
	if accepted.revision != 2 || accepted.keyID != KeyID(public) || accepted.sourceSHA256 != hex.EncodeToString(hash[:]) || !bytes.Equal(accepted.source, original) {
		t.Fatal("accepted history lost its source, key or revision")
	}
	if err := accepted.checkSource(original); err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{bytes.TrimSpace(source), append(bytes.Clone(source), ' '), nil} {
		if !errors.Is(accepted.checkSource(changed), ErrUnavailable) {
			t.Fatal("changed source matched its acceptance record")
		}
	}
	source[0] = 'x'
	if !bytes.Equal(accepted.source, original) {
		t.Fatal("caller input mutated decoded history")
	}
	record[0] = 'x'
	if err := accepted.checkSource(original); err != nil {
		t.Fatal("decoded history aliases input record", err)
	}
}

func TestAcceptanceRejectsRollbackReplayAndExpiredReplacement(t *testing.T) {
	prior, next, public, _, now := renewalFixture(t)
	latest, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	previousRecord, err := prepareAcceptance(prior, now)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := readAcceptance(previousRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := previous.checkAdvance(latest, now); err != nil {
		t.Fatal("valid newer policy rejected", err)
	}
	record, err := prepareAcceptance(latest, now)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := readAcceptance(record)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.revision != 3 {
		t.Fatal("last revision not retained")
	}
	if !errors.Is(accepted.checkSource(prior), ErrUnavailable) {
		t.Fatal("older signed source matched newer accepted history")
	}
	if !errors.Is(accepted.checkAdvance(prior, now), ErrDenied) || !errors.Is(accepted.checkAdvance(latest, now), ErrDenied) {
		t.Fatal("rollback or replay passed the accepted floor")
	}
	// Freshness is rechecked when recording a candidate; historic counter reads
	// can remain valid after expiry without granting historic permissions.
	later := now.Add(2 * time.Hour)
	if _, err := DecodeInstallation(accepted.source, later); err == nil {
		t.Fatal("expired accepted snapshot acquired authority")
	}
	if _, err := prepareAcceptance(latest, later); err == nil {
		t.Fatal("expired policy newly accepted")
	}
	historical, err := readAcceptance(record)
	if err != nil || historical.revision != 3 || historical.keyID != KeyID(public) {
		t.Fatal("expiry destroyed authenticated counter history", err)
	}
	if err := historical.checkAdvance(latest, later); err == nil {
		t.Fatal("expired replacement accepted")
	}
}

func TestAcceptanceRaisesRecoveryFloorAfterPrimaryCorruption(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	latest, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	record, err := prepareAcceptance(latest, now)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := readAcceptance(record)
	if err != nil {
		t.Fatal(err)
	}
	// A recovery approval can carry a too-low external minimum. Separate trusted
	// history must still prevent reusing the last accepted revision.
	recovery, public, _, recoveryNow := recoveryFixture(t, nil, time.Hour)
	_, candidate, err := recoveryTransition(nil, recovery, public, 2, recoveryNow)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(accepted.checkAdvance(candidate, recoveryNow), ErrDenied) {
		t.Fatal("corruption reset the accepted floor")
	}
	if _, err := DecodeInstallation(nil, now); err == nil {
		t.Fatal("empty primary gained authority from a retained snapshot")
	}
}

func TestAcceptanceStrictEncodingAndHistoryChecks(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	good, err := prepareAcceptance(prior, now)
	if err != nil {
		t.Fatal(err)
	}
	var installed Installation
	if err := json.Unmarshal(prior, &installed); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(installed.Envelope.Signature)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	installed.Envelope.Signature = base64.StdEncoding.EncodeToString(signature)
	changed, err := json.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	invalidHistory, _ := json.Marshal(acceptanceRecord{1, base64.StdEncoding.EncodeToString(changed)})
	for _, data := range [][]byte{
		nil, []byte("{}"), []byte("null"), bytes.Repeat([]byte(" "), maxAcceptanceBytes+1),
		bytes.Replace(good, []byte("\"schemaVersion\":1"), []byte("\"schemaVersion\":2"), 1),
		bytes.Replace(good, []byte("\"schemaVersion\":1"), []byte("\"schemaVersion\":1,\"schemaVersion\":1"), 1),
		bytes.Replace(good, []byte("\"installation\""), []byte("\"Installation\""), 1),
		[]byte("{\"schemaVersion\":1,\"installation\":null}"),
		[]byte("{\"schemaVersion\":1,\"installation\":\"\"}"),
		[]byte("{\"schemaVersion\":1,\"installation\":\"AA==\\n\"}"),
		append(bytes.Clone(good), []byte("{}")...), invalidHistory,
	} {
		if _, err := readAcceptance(data); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid accepted history was not blocked", err)
		}
	}
	for _, source := range [][]byte{nil, []byte("{}"), bytes.Repeat([]byte(" "), MaxInstallationBytes+1)} {
		if _, err := prepareAcceptance(source, now); err == nil {
			t.Fatal("invalid installation recorded as accepted")
		}
	}
	var absent *acceptedHistory
	if !errors.Is(absent.checkSource(prior), ErrUnavailable) || !errors.Is(absent.checkAdvance(prior, now), ErrUnavailable) {
		t.Fatal("missing history was an implicit permission")
	}
}

func TestAcceptanceSupportsMaximumBoundedSnapshot(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	source := append(bytes.Clone(prior), bytes.Repeat([]byte(" "), MaxInstallationBytes-len(prior))...)
	record, err := prepareAcceptance(source, now)
	if err != nil || len(record) > maxAcceptanceBytes {
		t.Fatal("bounded valid source could not be recorded", err)
	}
	accepted, err := readAcceptance(record)
	if err != nil || !bytes.Equal(accepted.source, source) {
		t.Fatal("maximum source changed", err)
	}
}

func FuzzAcceptedPolicyRecord(f *testing.F) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	payload, err := json.Marshal(Policy{SchemaVersion: 1, Revision: 2, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		f.Fatal(err)
	}
	signed, err := Sign(payload, private, now)
	if err != nil {
		f.Fatal(err)
	}
	source, err := PrepareInstallation(signed, public, now, 1)
	if err != nil {
		f.Fatal(err)
	}
	record, err := prepareAcceptance(source, now)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(record)
	f.Add([]byte("{}"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		accepted, err := readAcceptance(data)
		if err != nil {
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal("unclassified corrupt acceptance record", err)
			}
			return
		}
		if len(accepted.source) == 0 || len(accepted.source) > MaxInstallationBytes || accepted.revision == 0 || accepted.revision > maxSafeRevision {
			t.Fatal("invalid history accepted")
		}
		if err := accepted.checkSource(bytes.Clone(accepted.source)); err != nil {
			t.Fatal(err)
		}
		if err := accepted.checkAdvance(accepted.source, now); err == nil {
			t.Fatal("record authorized its own replay")
		}
	})
}
