package managed

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestIdentityPublicKeyCannotAuthorizePolicyOrRotation(t *testing.T) {
	f := rotationFixture(t)
	identity := ed25519.PublicKey(make([]byte, 32))
	identity[0] = 1
	signature := make([]byte, 64)
	signature[0] = 1
	policy := Policy{SchemaVersion: 1, Revision: 3, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}
	payload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	forged := Envelope{1, KeyID(identity), base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(signature)}
	encoded, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(identity, append([]byte(signatureDomain), payload...), signature) {
		t.Log("standard verifier accepts the identity-key fixture without a signing secret")
	}
	if _, err := Verify(encoded, identity, f.now, 2); err == nil {
		t.Error("degenerate identity key authorized policy without a signing secret")
	}
	if _, err := PublicKey(base64.StdEncoding.EncodeToString(identity)); err == nil {
		t.Error("degenerate identity public key parsed as acceptable trust")
	}
	if _, err := SignRotation(f.prior, encoded, identity, f.oldPrivate, f.now); err == nil {
		t.Error("rotation signer accepted forged replacement proof of possession")
	}
	rotation := mutateRotationRequest(t, f, func(r *rotationRequest) {
		r.NextPublicKey = base64.StdEncoding.EncodeToString(identity)
		r.NextEnvelope = forged
	})
	if _, _, err := rotationTransition(f.prior, rotation, f.now); err == nil {
		t.Error("authorized transition installed a degenerate replacement key")
	}
}

func TestManagedKeysRejectAllSmallOrderSignsAndNoncanonicalCoordinates(t *testing.T) {
	coordinates := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	for _, coordinate := range coordinates {
		key, err := hex.DecodeString(coordinate)
		if err != nil {
			t.Fatal(err)
		}
		for _, sign := range []byte{0, 0x80} {
			key[31] = (key[31] & 0x7f) | sign
			if err := validatePublicKey(key); err == nil {
				t.Fatalf("low-order key accepted: %x", key)
			}
			if _, err := PublicKey(base64.StdEncoding.EncodeToString(key)); err == nil {
				t.Fatal("key parser bypassed low-order check")
			}
		}
	}
	// Every noncanonical y in [p,2^255) must fail for both sign bits.
	for low := 0xed; low <= 0xff; low++ {
		key := make([]byte, 32)
		for index := range key {
			key[index] = 0xff
		}
		key[0] = byte(low)
		for _, sign := range []byte{0, 0x80} {
			key[31] = 0x7f | sign
			if err := validatePublicKey(key); err == nil {
				t.Fatalf("noncanonical y accepted: %x", key)
			}
		}
	}
	for index := 0; index < 32; index++ {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePublicKey(public); err != nil {
			t.Fatal("generated signing key rejected", err)
		}
		decoded, err := PublicKey(base64.StdEncoding.EncodeToString(public))
		if err != nil || !public.Equal(decoded) {
			t.Fatal("canonical key changed", err)
		}
	}
}
