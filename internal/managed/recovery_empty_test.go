package managed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestEmptySourceSignedRecoveryBindsPresenceKeyAndFloor(t *testing.T) {
	_, next, public, private, now := renewalFixture(t)
	signed, err := SignRecovery(nil, next, private, 2, now, time.Hour)
	if err != nil {
		t.Fatal("existing empty source cannot receive a signed recovery approval", err)
	}
	review, candidate, err := recoveryTransition(nil, signed, public, 2, now)
	digest := sha256.Sum256(nil)
	if err != nil || review.PreviousSourceSHA256 != hex.EncodeToString(digest[:]) || review.PreviousAuthenticated || !review.SignatureValid || review.RuntimeEnforced {
		t.Fatal("empty source acquired authority or lost exact binding", review, err)
	}
	if _, err := DecodeInstallation(nil, now); err == nil {
		t.Fatal("empty source became runtime authority")
	}
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		source []byte
		key    ed25519.PublicKey
		floor  uint64
		when   time.Time
	}{
		{[]byte{0}, public, 2, now}, {candidate, public, 2, now}, {nil, wrong, 2, now}, {nil, public, 1, now}, {nil, public, 3, now}, {nil, public, 2, now.Add(time.Hour)},
	} {
		if _, err := VerifyRecovery(check.source, signed, check.key, check.floor, check.when); err == nil {
			t.Fatal("wrong source, replay, key, floor or expiry accepted")
		}
	}
	absent := &fakeInstallationTransaction{present: false}
	result, err := commitRecovery(absent, signed, public, 2, func() time.Time { return now })
	if err == nil || result.Committed || absent.stageCalls != 0 || absent.commitCalls != 0 || absent.closeCalls != 1 {
		t.Fatal("empty-source approval enrolled an absent source", result, err)
	}
}
