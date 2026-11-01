package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) ([]byte, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{SchemaVersion: 1, Revision: 2, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Launches: []LaunchRule{}, Workflows: []WorkflowRule{}}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return data, public, private, now
}

func TestSignedReviewAuthenticatesExactBytesAndPinnedKey(t *testing.T) {
	payload, public, private, now := fixture(t)
	signed, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(signed, public, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Policy.Revision != 2 || !result.SignatureValid || result.RuntimeEnforced {
		t.Fatalf("misleading review result: %+v", result)
	}
	if strings.Contains(string(signed), base64.StdEncoding.EncodeToString(private)) {
		t.Fatal("private key in deployment envelope")
	}
	var envelope Envelope
	if err := json.Unmarshal(signed, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(append(payload, ' '))
	tampered, _ := json.Marshal(envelope)
	if _, err := Verify(tampered, public, now, 0); err == nil {
		t.Fatal("payload whitespace tampering accepted")
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope.KeyID = KeyID(other)
	swapped, _ := json.Marshal(envelope)
	if _, err := Verify(swapped, other, now, 0); err == nil {
		t.Fatal("key substitution accepted")
	}
	envelope.KeyID = KeyID(public)
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	wrongDomain, _ := json.Marshal(envelope)
	if _, err := Verify(wrongDomain, public, now, 0); err == nil {
		t.Fatal("signature for another protocol accepted")
	}
}

func TestTrustedRevisionAndValidityWindow(t *testing.T) {
	payload, public, private, now := fixture(t)
	signed, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, minimum := range []uint64{2, 3, ^uint64(0)} {
		if _, err := Verify(signed, public, now, minimum); err == nil {
			t.Fatalf("stale revision accepted against %d", minimum)
		}
	}
	if _, err := Verify(signed, public, now.Add(time.Hour), 0); err == nil {
		t.Fatal("expired policy accepted at expiry boundary")
	}
	if _, err := Verify(signed, public, now.Add(-2*time.Hour), 0); err == nil {
		t.Fatal("future issuance accepted")
	}
	if _, err := Verify(signed, public, time.Time{}, 0); err == nil {
		t.Fatal("missing trusted clock accepted")
	}
}

func TestStrictSignedDocumentValidation(t *testing.T) {
	payload, public, private, now := fixture(t)
	duplicate := bytes.Replace(payload, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1)
	unknown := bytes.Replace(payload, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"extra":true`), 1)
	badRevision := bytes.Replace(payload, []byte(`"revision":2`), []byte(`"revision":9007199254740992`), 1)
	for name, data := range map[string][]byte{"duplicate": duplicate, "unknown": unknown, "trailing": append(payload, []byte(` {}`)...), "null": []byte(`null`), "case alias": bytes.Replace(payload, []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1), "case override": bytes.Replace(payload, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"SchemaVersion":2`), 1), "unsafe revision": badRevision, "oversize": bytes.Repeat([]byte(" "), MaxPolicyBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(data, private, now); err == nil {
				t.Fatal("invalid policy signed")
			}
			external := Envelope{1, KeyID(public), base64.StdEncoding.EncodeToString(data), base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(signatureDomain), data...)))}
			encoded, err := json.Marshal(external)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(encoded, public, now, 0); err == nil {
				t.Fatal("invalid document accepted from external signer")
			}

		})
	}
	signed, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	duplicate = bytes.Replace(signed, []byte(`"schemaVersion": 1`), []byte(`"schemaVersion": 1,"schemaVersion":1`), 1)
	if _, err := Verify(duplicate, public, now, 0); err == nil {
		t.Fatal("duplicate envelope accepted")
	}
	if _, err := Verify(bytes.Repeat([]byte(" "), MaxEnvelopeBytes+1), public, now, 0); err == nil {
		t.Fatal("oversize envelope accepted")
	}
	var envelope Envelope
	if err := json.Unmarshal(signed, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signature += "\n"
	noncanonical, _ := json.Marshal(envelope)
	if _, err := Verify(noncanonical, public, now, 0); err == nil {
		t.Fatal("noncanonical signature encoding accepted")
	}
	if _, err := PublicKey(base64.StdEncoding.EncodeToString(public) + "\n"); err == nil {
		t.Fatal("noncanonical public key accepted")
	}
	if _, err := Sign(payload, ed25519.PrivateKey{1}, now); err == nil {
		t.Fatal("short signing key accepted")
	}
	broken := append(ed25519.PrivateKey(nil), private...)
	broken[63] ^= 1
	if _, err := Sign(payload, broken, now); err == nil {
		t.Fatal("inconsistent signing key accepted")
	}
	if _, err := Verify(signed, ed25519.PublicKey{1}, now, 0); err == nil {
		t.Fatal("short public key accepted")
	}
}

func TestAllowlistValidation(t *testing.T) {
	payload, _, _, now := fixture(t)
	var p Policy
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	rule := LaunchRule{Engine: "byedpi", InputSHA256: hash, BinarySHA256: hash}
	p.Launches = []LaunchRule{rule}
	data, _ := json.Marshal(p)
	if _, err := DecodePolicy(data, now, 0); err != nil {
		t.Fatal(err)
	}
	p.Launches = append(p.Launches, rule)
	data, _ = json.Marshal(p)
	if _, err := DecodePolicy(data, now, 0); err == nil {
		t.Fatal("duplicate launch intent accepted")
	}
	p.Launches = []LaunchRule{rule}
	p.Launches[0].BinarySHA256 = strings.Repeat("A", 64)
	data, _ = json.Marshal(p)
	if _, err := DecodePolicy(data, now, 0); err == nil {
		t.Fatal("ambiguous hash spelling accepted")
	}
	// Nested duplicate fields must fail even when a valid signature authenticates them.
	p.Launches = []LaunchRule{rule}
	data, _ = json.Marshal(p)
	data = bytes.Replace(data, []byte(`"engine":"byedpi"`), []byte(`"engine":"byedpi","engine":"byedpi"`), 1)
	if _, err := DecodePolicy(data, now, 0); err == nil {
		t.Fatal("nested duplicate rule field accepted")
	}
	p.Launches = nil
	p.Workflows = make([]WorkflowRule, 129)
	data, _ = json.Marshal(p)
	if _, err := DecodePolicy(data, now, 0); err == nil {
		t.Fatal("oversized workflow allowlist accepted")
	}
}

func FuzzDecodePolicy(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":1,"revision":1,"issuedAt":"2026-11-01T11:00:00Z","expiresAt":"2026-11-01T13:00:00Z","launches":[],"workflows":[]}`))
	f.Add([]byte(`{"schemaVersion":1,"SchemaVersion":2}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodePolicy(data, time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), 0)
	})
}

func FuzzVerifyEnvelope(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":1,"keyId":"invalid","payload":"","signature":""}`))
	f.Add([]byte(`null`))
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := private.Public().(ed25519.PublicKey)
	valid, _ := Sign([]byte(`{"schemaVersion":1,"revision":1,"issuedAt":"2026-11-01T11:00:00Z","expiresAt":"2026-11-01T13:00:00Z","launches":[],"workflows":[]}`), private, time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC))
	f.Add(valid)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Verify(data, public, time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), 0)
	})
}

func TestPinnedDownloadRulesRejectAmbiguousSources(t *testing.T) {
	data, _, _, now := fixture(t)
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	pin := DownloadRule{URL: "https://github.com/hufrea/byedpi/releases/download/v-test/component.zip", SHA256: strings.Repeat("a", 64)}
	p.Downloads = []DownloadRule{pin}
	data, _ = json.Marshal(p)
	if _, err := DecodePolicy(data, now, 0); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://example.org/file", "https://user:password@example.org/file", "https://example.org/file#fragment", "relative.zip"} {
		p.Downloads = []DownloadRule{{URL: bad, SHA256: pin.SHA256}}
		data, _ = json.Marshal(p)
		if _, err := DecodePolicy(data, now, 0); err == nil {
			t.Fatal("invalid download source accepted", bad)
		}
	}
	p.Downloads = []DownloadRule{pin, pin}
	data, _ = json.Marshal(p)
	if _, err := DecodePolicy(data, now, 0); err == nil {
		t.Fatal("duplicate download authority accepted")
	}
}
