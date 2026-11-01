package managed

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
)

// Validate the public encoding before signature verification. Ed25519's group
// equation alone can accept degenerate low-order public keys with no secret.
// This check handles public bytes only; the standard library still performs
// curve decoding and every signature operation.
func validatePublicKey(key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key length")
	}
	var y [32]byte
	copy(y[:], key)
	y[31] &= 0x7f // The remaining bit encodes the x-coordinate sign.
	// RFC 8032 compressed y must be less than p = 2^255 - 19.
	var prime [32]byte
	for index := range prime {
		prime[index] = 0xff
	}
	prime[0] = 0xed
	prime[31] = 0x7f
	canonical := false
	for index := 31; index >= 0; index-- {
		if y[index] < prime[index] {
			canonical = true
			break
		}
		if y[index] > prime[index] {
			break
		}
	}
	if !canonical {
		return errors.New("noncanonical Ed25519 public key encoding")
	}
	// Five y coordinates cover all eight small-order points when both x signs
	// are considered. Mathematical values cross-checked against the tagged
	// libsodium reference ge25519_has_small_order coordinate set:
	// https://github.com/jedisct1/libsodium/blob/1.0.20-RELEASE/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
	switch hex.EncodeToString(y[:]) {
	case "0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f":
		return errors.New("low-order Ed25519 public key is not acceptable signing authority")
	}
	return nil
}
