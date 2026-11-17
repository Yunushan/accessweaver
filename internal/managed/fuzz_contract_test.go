package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

var fuzzPolicyNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func fuzzPolicyPayload(tb testing.TB, populated bool) []byte {
	tb.Helper()
	p := Policy{SchemaVersion: 1, Revision: 2, IssuedAt: fuzzPolicyNow.Add(-time.Minute), ExpiresAt: fuzzPolicyNow.Add(time.Hour), Launches: []LaunchRule{}, Workflows: []WorkflowRule{}}
	if populated {
		p.AllowDiagnostics = true
		p.AllowDownloads = true
		p.AllowProfileChanges = true
		p.RequireProfileAudit = true
		p.Downloads = []DownloadRule{{URL: "https://fixture.invalid/component.zip", SHA256: strings.Repeat("a", 64)}}
		p.Launches = []LaunchRule{{Engine: "byedpi", InputSHA256: strings.Repeat("b", 64), BinarySHA256: strings.Repeat("c", 64)}}
		p.Workflows = []WorkflowRule{{Action: "discover", InputSHA256: strings.Repeat("d", 64)}}
	}
	data, err := json.Marshal(p)
	if err != nil {
		tb.Fatal("synthetic policy encoding failed")
	}
	if _, err := DecodePolicy(data, fuzzPolicyNow, 0); err != nil {
		tb.Fatal("synthetic policy seed invalid")
	}
	return data
}

func assertFuzzPolicy(t *testing.T, p Policy) {
	t.Helper()
	if p.SchemaVersion != 1 || p.Revision == 0 || p.Revision > maxSafeRevision || p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(fuzzPolicyNow) || !p.ExpiresAt.After(p.IssuedAt) || p.IssuedAt.After(fuzzPolicyNow.Add(5*time.Minute)) {
		t.Fatal("accepted policy broke validity or revision bounds")
	}
	if len(p.Downloads) > 128 || len(p.Launches) > 128 || len(p.Workflows) > 128 {
		t.Fatal("accepted allowlist exceeds bound")
	}
	validHash := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
	}
	validName := func(value string) bool {
		if len(value) < 2 || len(value) > 50 || value[0] < 'a' || value[0] > 'z' {
			return false
		}
		for _, c := range value {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		return true
	}
	downloads, launches, workflows := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, rule := range p.Downloads {
		parsed, err := url.Parse(rule.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || len(rule.URL) > 4096 || !validHash(rule.SHA256) || downloads[rule.URL] {
			t.Fatal("accepted download rule breaks source/hash uniqueness")
		}
		downloads[rule.URL] = true
	}
	for _, rule := range p.Launches {
		key := rule.Engine + ":" + rule.InputSHA256
		if !validName(rule.Engine) || !validHash(rule.InputSHA256) || !validHash(rule.BinarySHA256) || rule.ConfigSHA256 != "" && !validHash(rule.ConfigSHA256) || launches[key] {
			t.Fatal("accepted launch rule breaks name/hash uniqueness")
		}
		launches[key] = true
	}
	for _, rule := range p.Workflows {
		key := rule.Action + ":" + rule.InputSHA256
		if !validName(rule.Action) || !validHash(rule.InputSHA256) || workflows[key] {
			t.Fatal("accepted workflow rule breaks name/hash uniqueness")
		}
		workflows[key] = true
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		t.Fatal("accepted policy cannot be encoded")
	}
	// JSON's default HTML escaping can expand an accepted signed payload past
	// its input cap. That encoding is not required to be a valid new input.
	if len(canonical) > MaxPolicyBytes {
		return
	}
	again, err := DecodePolicy(canonical, fuzzPolicyNow, 0)
	if err != nil {
		t.Fatal("accepted policy did not round trip")
	}
	encoded, err := json.Marshal(again)
	if err != nil || !bytes.Equal(canonical, encoded) {
		t.Fatal("accepted policy lost canonical field meaning")
	}
	if _, err := DecodePolicy(canonical, fuzzPolicyNow, p.Revision); err == nil {
		t.Fatal("accepted policy replay exceeded its trusted floor")
	}
	if _, err := DecodePolicy(canonical, p.ExpiresAt, 0); err == nil {
		t.Fatal("accepted policy remained valid at expiry")
	}
}

func assertFuzzVerified(t *testing.T, data []byte, public ed25519.PublicKey, result Verified) {
	t.Helper()
	assertFuzzPolicy(t, result.Policy)
	var envelope Envelope
	if json.Unmarshal(data, &envelope) != nil {
		t.Fatal("accepted envelope unavailable")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal("accepted payload not base64")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil {
		t.Fatal("accepted signature not base64")
	}
	digest := sha256.Sum256(payload)
	if !result.SignatureValid || result.RuntimeEnforced || result.KeyID != KeyID(public) || result.PayloadSHA256 != hex.EncodeToString(digest[:]) || !ed25519.Verify(public, append([]byte(signatureDomain), payload...), signature) {
		t.Fatal("accepted envelope lost pinned authenticity or overstated enforcement")
	}
	if _, err := Verify(data, public, fuzzPolicyNow, result.Policy.Revision); err == nil {
		t.Fatal("verified envelope authorized replay")
	}
	if _, err := Verify(data, public, result.Policy.ExpiresAt, 0); err == nil {
		t.Fatal("verified envelope ignored expiry")
	}
	signature[0] ^= 1
	envelope.Signature = base64.StdEncoding.EncodeToString(signature)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal("signature mutation encoding failed")
	}
	if _, err := Verify(tampered, public, fuzzPolicyNow, 0); err == nil {
		t.Fatal("changed signature accepted")
	}
}

func deterministicFuzzRotation(tb testing.TB) rotationFixtureData {
	tb.Helper()
	oldPrivate := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	oldPublic := oldPrivate.Public().(ed25519.PublicKey)
	newPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	newPublic := newPrivate.Public().(ed25519.PublicKey)
	oldPolicy := Policy{SchemaVersion: 1, Revision: 1, IssuedAt: fuzzPolicyNow.Add(-time.Minute), ExpiresAt: fuzzPolicyNow.Add(time.Hour)}
	payload, err := json.Marshal(oldPolicy)
	if err != nil {
		tb.Fatal("synthetic prior encoding failed")
	}
	signed, err := Sign(payload, oldPrivate, fuzzPolicyNow)
	if err != nil {
		tb.Fatal("synthetic prior signing failed")
	}
	prior, err := PrepareInstallation(signed, oldPublic, fuzzPolicyNow, 0)
	if err != nil {
		tb.Fatal("synthetic installation failed")
	}
	next, err := Sign(fuzzPolicyPayload(tb, true), newPrivate, fuzzPolicyNow)
	if err != nil {
		tb.Fatal("synthetic successor signing failed")
	}
	rotation, err := SignRotation(prior, next, newPublic, oldPrivate, fuzzPolicyNow)
	if err != nil {
		tb.Fatal("synthetic rotation failed")
	}
	return rotationFixtureData{prior: prior, next: next, rotation: rotation, oldPublic: oldPublic, newPublic: newPublic, oldPrivate: oldPrivate, newPrivate: newPrivate, now: fuzzPolicyNow}
}

func assertFuzzRotation(t *testing.T, f rotationFixtureData, data []byte, review RotationReview) {
	t.Helper()
	if !review.SignatureValid || review.RuntimeEnforced || review.PreviousKeyID != KeyID(f.oldPublic) || review.PreviousRevision != 1 || review.Next.KeyID == review.PreviousKeyID || !review.Next.SignatureValid || review.Next.RuntimeEnforced || review.Next.Policy.Revision <= review.PreviousRevision {
		t.Fatal("accepted rotation lost authority transition bounds")
	}
	var prior Installation
	if json.Unmarshal(f.prior, &prior) != nil {
		t.Fatal("synthetic prior unavailable")
	}
	priorPayload, err := base64.StdEncoding.DecodeString(prior.Envelope.Payload)
	if err != nil {
		t.Fatal("synthetic prior payload unavailable")
	}
	previousDigest := sha256.Sum256(priorPayload)
	if review.PreviousPayloadSHA256 != hex.EncodeToString(previousDigest[:]) {
		t.Fatal("accepted rotation lost exact prior payload binding")
	}
	var outer Envelope
	if json.Unmarshal(data, &outer) != nil {
		t.Fatal("accepted rotation envelope unavailable")
	}
	payload, err := base64.StdEncoding.DecodeString(outer.Payload)
	if err != nil {
		t.Fatal("accepted rotation payload unavailable")
	}
	var request rotationRequest
	if json.Unmarshal(payload, &request) != nil {
		t.Fatal("accepted rotation request unavailable")
	}
	request.PreviousPayloadSHA256 = strings.Repeat("f", 64)
	if request.PreviousPayloadSHA256 == review.PreviousPayloadSHA256 {
		request.PreviousPayloadSHA256 = strings.Repeat("e", 64)
	}
	changed, err := json.Marshal(request)
	if err != nil {
		t.Fatal("prior binding mutation encoding failed")
	}
	outer.Payload = base64.StdEncoding.EncodeToString(changed)
	outer.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.oldPrivate, append([]byte(rotationDomain), changed...)))
	changed, err = json.Marshal(outer)
	if err != nil {
		t.Fatal("prior binding envelope encoding failed")
	}
	if _, err := VerifyRotation(f.prior, changed, f.oldPublic, f.now); err == nil {
		t.Fatal("validly signed wrong-prior binding accepted")
	}
	assertFuzzPolicy(t, review.Next.Policy)
	if _, err := VerifyRotation(f.prior, data, f.oldPublic, review.Next.Policy.ExpiresAt); err == nil {
		t.Fatal("accepted rotation ignored successor expiry")
	}

	candidate, result, err := rotationTransition(f.prior, data, f.now)
	if err != nil || result.Revision != review.Next.Policy.Revision || result.KeyID != review.Next.KeyID || result.PreviousRevision != review.PreviousRevision {
		t.Fatal("accepted rotation did not prepare the same successor")
	}
	installed, err := DecodeInstallation(candidate, f.now)
	if err != nil || installed.verified.KeyID != review.Next.KeyID || installed.verified.PayloadSHA256 != review.Next.PayloadSHA256 {
		t.Fatal("accepted rotation changed successor content")
	}
	var value Installation
	if json.Unmarshal(candidate, &value) != nil {
		t.Fatal("accepted successor unavailable")
	}
	public, err := PublicKey(value.PublicKey)
	if err != nil {
		t.Fatal("accepted successor key unavailable")
	}
	if _, err := VerifyRotation(candidate, data, public, f.now); err == nil {
		t.Fatal("accepted rotation authorized its own replay")
	}
}

// The fixture signs arbitrary mutated bytes, including invalid policy JSON. This
// reaches the authenticated payload decoder instead of stopping at bad signatures.
func FuzzVerifySignedPolicyPayload(f *testing.F) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	f.Add(fuzzPolicyPayload(f, false), false)
	f.Add(fuzzPolicyPayload(f, true), false)
	f.Add(fuzzPolicyPayload(f, true), true)
	f.Add(bytes.Replace(fuzzPolicyPayload(f, false), []byte("2026-11-01T13:00:00Z"), []byte("2026-11-03T13:00:00+24:00"), 1), false)

	f.Add([]byte(`{}`), false)
	f.Fuzz(func(t *testing.T, payload []byte, wrongDomain bool) {
		if len(payload) > MaxPolicyBytes {
			return
		}
		domain := signatureDomain
		if wrongDomain {
			domain = rotationDomain
		}
		envelope := Envelope{1, KeyID(public), base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(domain), payload...)))}
		data, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal("synthetic envelope encoding failed")
		}
		result, err := Verify(data, public, fuzzPolicyNow, 0)
		_, policyError := DecodePolicy(payload, fuzzPolicyNow, 0)
		if wrongDomain || policyError != nil {
			if err == nil || result.SignatureValid || result.RuntimeEnforced {
				t.Fatal("wrong-domain or invalid authenticated policy was accepted")
			}
			return
		}
		if err != nil {
			t.Fatal("valid authenticated policy rejected")
		}
		assertFuzzVerified(t, data, public, result)
	})
}

func FuzzVerifySignedRotationPayload(f *testing.F) {
	fixture := deterministicFuzzRotation(f)
	var envelope Envelope
	if json.Unmarshal(fixture.rotation, &envelope) != nil {
		f.Fatal("synthetic rotation envelope unavailable")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		f.Fatal("synthetic rotation payload unavailable")
	}
	f.Add(payload)
	f.Add([]byte(`{}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > MaxRotationPayloadBytes {
			return
		}
		envelope := Envelope{1, KeyID(fixture.oldPublic), base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.oldPrivate, append([]byte(rotationDomain), payload...)))}
		data, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal("synthetic rotation payload encoding failed")
		}
		review, err := VerifyRotation(fixture.prior, data, fixture.oldPublic, fixture.now)
		if err == nil {
			assertFuzzRotation(t, fixture, data, review)
		} else if review.SignatureValid || review.RuntimeEnforced {
			t.Fatal("rejected rotation published usable review")
		}
	})
}

func TestFuzzPolicyOracleHandlesExpandedJSONRepresentation(t *testing.T) {
	p := Policy{SchemaVersion: 1, Revision: 2, IssuedAt: fuzzPolicyNow.Add(-time.Minute), ExpiresAt: fuzzPolicyNow.Add(time.Hour)}
	for i := 0; i < 20; i++ {
		p.Downloads = append(p.Downloads, DownloadRule{URL: "https://fixture.invalid/" + strconv.Itoa(i) + "?value=" + strings.Repeat("&", 1200), SHA256: strings.Repeat("a", 64)})
	}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(p) != nil || raw.Len() > MaxPolicyBytes {
		t.Fatal("bounded raw policy fixture unavailable")
	}
	accepted, err := DecodePolicy(raw.Bytes(), fuzzPolicyNow, 0)
	if err != nil {
		t.Fatal("valid raw fixture was rejected")
	}
	expanded, err := json.Marshal(accepted)
	if err != nil || len(expanded) <= MaxPolicyBytes {
		t.Fatal("expanded representation fixture unavailable")
	}
	assertFuzzPolicy(t, accepted)
	if _, err := DecodePolicy(raw.Bytes(), fuzzPolicyNow, accepted.Revision); err == nil {
		t.Fatal("raw policy replay accepted")
	}
	if _, err := DecodePolicy(raw.Bytes(), accepted.ExpiresAt, 0); err == nil {
		t.Fatal("raw policy expiry ignored")
	}
}

func TestPolicyRejectsTimestampParserSerializerMismatch(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	for _, value := range []string{"2026-11-03T13:00:00+24:00", "2026-11-03T13:00:00+00:60", "2026-11-03T13:00:00,123Z", "2026-11-03T9:00:00Z"} {
		var fields map[string]json.RawMessage
		if json.Unmarshal(fuzzPolicyPayload(t, false), &fields) != nil {
			t.Fatal("timestamp fixture unavailable")
		}
		fields["expiresAt"], _ = json.Marshal(value)
		payload, err := json.Marshal(fields)
		if err != nil {
			t.Fatal("timestamp fixture encoding failed")
		}
		if _, err := DecodePolicy(payload, fuzzPolicyNow, 0); err == nil {
			t.Fatal("invalid policy timestamp accepted")
		}
		if _, err := Sign(payload, private, fuzzPolicyNow); err == nil {
			t.Fatal("invalid policy timestamp signed")
		}
		envelope := Envelope{1, KeyID(public), base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(signatureDomain), payload...)))}
		signed, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal("synthetic signed timestamp fixture unavailable")
		}
		if result, err := Verify(signed, public, fuzzPolicyNow, 0); err == nil || result.SignatureValid || result.RuntimeEnforced {
			t.Fatal("authenticated invalid timestamp produced a verified policy")
		}
		installation, err := json.Marshal(Installation{1, base64.StdEncoding.EncodeToString(public), 0, envelope})
		if err != nil {
			t.Fatal("synthetic installation fixture unavailable")
		}
		if authority, err := DecodeInstallation(installation, fuzzPolicyNow); err == nil || authority != nil {
			t.Fatal("invalid signed timestamp produced installation authority")
		}
	}
	// Control the actual SDK mismatch: permissive parsing succeeds, while JSON
	// serialization cannot represent the accepted timezone. No machine state used.
	var parsed time.Time
	if json.Unmarshal([]byte(`"2026-11-03T13:00:00+24:00"`), &parsed) != nil {
		t.Fatal("pinned SDK parser control changed")
	}
	if _, err := parsed.MarshalJSON(); err == nil {
		t.Fatal("pinned SDK serializer mismatch control changed")
	}
}
