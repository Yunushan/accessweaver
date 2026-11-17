package managed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Complete schema immediately before the reconciliation permission, including
// the already-existing retirement permission. This models a prior strict
// reader; it does not execute an old product binary.
type lifecycleReconciliationPriorPolicy struct {
	Downloads                      []DownloadRule `json:"downloads,omitempty"`
	SchemaVersion                  int            `json:"schemaVersion"`
	Revision                       uint64         `json:"revision"`
	IssuedAt                       time.Time      `json:"issuedAt"`
	ExpiresAt                      time.Time      `json:"expiresAt"`
	AllowDownloads                 bool           `json:"allowDownloads"`
	AllowDiagnostics               bool           `json:"allowDiagnostics"`
	AllowProfileChanges            bool           `json:"allowProfileChanges"`
	RequireProfileAudit            bool           `json:"requireProfileAudit,omitempty"`
	AllowWorkflowHistoryRetirement bool           `json:"allowWorkflowHistoryRetirement,omitempty"`
	Launches                       []LaunchRule   `json:"launches"`
	Workflows                      []WorkflowRule `json:"workflows"`
}

func TestLifecycleReconciliationPolicyPreservesExistingSignedBytes(t *testing.T) {
	original, public, private, now := fixture(t)
	var prior lifecycleReconciliationPriorPolicy
	if strictJSON(original, MaxPolicyBytes, &prior) != nil {
		t.Fatal("prior complete policy fixture is unavailable")
	}
	prior.AllowWorkflowHistoryRetirement = true
	legacy, err := json.Marshal(prior)
	if err != nil {
		t.Fatal("prior policy fixture could not be encoded")
	}
	signed, err := Sign(legacy, private, now)
	if err != nil {
		t.Fatal("existing signed policy was rejected")
	}
	verified, err := Verify(signed, public, now, 0)
	if err != nil || verified.Policy.AllowWorkflowLifecycleReconciliation || !verified.Policy.AllowWorkflowHistoryRetirement {
		t.Fatal("new permission changed existing signed policy intent")
	}
	encoded, err := json.Marshal(verified.Policy)
	if err != nil || !bytes.Equal(encoded, legacy) {
		t.Fatal("false omitted reconciliation permission changed existing policy bytes")
	}
	var envelope Envelope
	if json.Unmarshal(signed, &envelope) != nil || envelope.Payload != base64.StdEncoding.EncodeToString(legacy) {
		t.Fatal("existing exact signed payload bytes were normalized")
	}
	if strictJSON(legacy, MaxPolicyBytes, &prior) != nil {
		t.Fatal("modeled prior reader rejected existing retirement permission")
	}
	for _, value := range []string{"false", "true"} {
		changed := bytes.Replace(legacy, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"allowWorkflowLifecycleReconciliation":`+value), 1)
		signed, err := Sign(changed, private, now)
		if err != nil {
			t.Fatal("canonical optional permission could not be signed")
		}
		verified, err := Verify(signed, public, now, 0)
		if err != nil || verified.Policy.AllowWorkflowLifecycleReconciliation != (value == "true") {
			t.Fatal("signed reconciliation permission was not retained exactly")
		}
		if strictJSON(changed, MaxPolicyBytes, &prior) == nil {
			t.Fatal("modeled prior strict reader ignored the new permission")
		}
		if _, err := Verify(signed, public, now.Add(time.Hour), 0); err == nil {
			t.Fatal("expired signed reconciliation permission remained valid")
		}
		if json.Unmarshal(signed, &envelope) != nil {
			t.Fatal("signed reconciliation envelope is unavailable")
		}
		replacement := "false"
		if value == "false" {
			replacement = "true"
		}
		tampered := bytes.Replace(changed, []byte(`"allowWorkflowLifecycleReconciliation":`+value), []byte(`"allowWorkflowLifecycleReconciliation":`+replacement), 1)
		envelope.Payload = base64.StdEncoding.EncodeToString(tampered)
		forged, _ := json.Marshal(envelope)
		if _, err := Verify(forged, public, now, 0); err == nil {
			t.Fatal("reconciliation permission changed without a new signature")
		}
	}
}

func TestLifecycleReconciliationPolicyRejectsAmbiguousPermission(t *testing.T) {
	payload, public, private, now := fixture(t)
	for name, field := range map[string]string{
		"null":              `"allowWorkflowLifecycleReconciliation":null`,
		"string":            `"allowWorkflowLifecycleReconciliation":"PRIVATE_PERMISSION"`,
		"number":            `"allowWorkflowLifecycleReconciliation":1`,
		"array":             `"allowWorkflowLifecycleReconciliation":[]`,
		"object":            `"allowWorkflowLifecycleReconciliation":{}`,
		"case-alias":        `"AllowWorkflowLifecycleReconciliation":true`,
		"lowercase-alias":   `"allowworkflowlifecyclereconciliation":true`,
		"duplicate":         `"allowWorkflowLifecycleReconciliation":true,"allowWorkflowLifecycleReconciliation":false`,
		"escaped-duplicate": `"allowWorkflowLifecycleReconciliation":true,"\u0061llowWorkflowLifecycleReconciliation":false`,
		"case-override":     `"allowWorkflowLifecycleReconciliation":true,"AllowWorkflowLifecycleReconciliation":false`,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := bytes.Replace(payload, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,`+field), 1)
			if _, err := Sign(invalid, private, now); err == nil || strings.Contains(err.Error(), "PRIVATE_PERMISSION") {
				t.Fatal("ambiguous permission was signed or exposed its private value")
			}
			external := Envelope{1, KeyID(public), base64.StdEncoding.EncodeToString(invalid), base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(signatureDomain), invalid...)))}
			encoded, err := json.Marshal(external)
			if err != nil {
				t.Fatal("external signed fixture could not be encoded")
			}
			if _, err := Verify(encoded, public, now, 0); err == nil || strings.Contains(err.Error(), "PRIVATE_PERMISSION") {
				t.Fatal("ambiguous externally signed reconciliation permission was accepted or leaked")
			}
		})
	}
}

func TestLifecycleReconciliationAuthorizationIsIndependent(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, policy := range []Policy{
		{},
		{AllowWorkflowHistoryRetirement: true},
		{AllowProfileChanges: true, RequireProfileAudit: true},
		{AllowDiagnostics: true, AllowDownloads: true},
		{Workflows: []WorkflowRule{{Action: "lifecycle-reconciliation", InputSHA256: digest}}},
		{Launches: []LaunchRule{{Engine: "byedpi", InputSHA256: digest, BinarySHA256: digest}}},
	} {
		authority := liveAuthorizationAuthority(t, policy)
		guard := NewGuard(func() (*Authority, error) { return authority, nil })
		if grant, err := guard.AuthorizeLifecycleReconciliation(); grant != nil || !errors.Is(err, ErrDenied) {
			t.Fatal("another permission substituted for reconciliation authorization")
		}
	}
	authority := liveAuthorizationAuthority(t, Policy{AllowWorkflowLifecycleReconciliation: true})
	guard := NewGuard(func() (*Authority, error) { return authority, nil })
	preview, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil || preview == nil || preview.Check() != nil {
		t.Fatal("explicit current reconciliation permission was denied")
	}
	apply, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil || apply == nil || apply == preview || apply.Check() != nil {
		t.Fatal("separate preview and apply acquisition did not produce fresh retained grants")
	}
	if grant, err := guard.AuthorizeHistoryRetirement(); grant != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("reconciliation granted history retirement")
	}
	if !errors.Is(guard.ProfileChanges(), ErrDenied) || !errors.Is(guard.Diagnostics(), ErrDenied) || !errors.Is(guard.Launch(LaunchRequest{}), ErrDenied) || !errors.Is(guard.ServiceHost(), ErrDenied) {
		t.Fatal("reconciliation permission granted an unrelated action")
	}
	if _, err := guard.Workflow("discover", digest, nil); !errors.Is(err, ErrDenied) {
		t.Fatal("reconciliation permission granted native workflow execution")
	}
	unmanaged := NewGuard(func() (*Authority, error) { return nil, nil })
	if grant, err := unmanaged.AuthorizeLifecycleReconciliation(); err != nil || grant == nil || grant.Check() != nil {
		t.Fatal("verified unmanaged state was unexpectedly rejected")
	}
	for _, cause := range []error{ErrUnavailable, errors.New("source verification failed")} {
		broken := NewGuard(func() (*Authority, error) { return nil, cause })
		if grant, err := broken.AuthorizeLifecycleReconciliation(); grant != nil || !errors.Is(err, cause) {
			t.Fatal("invalid or unavailable source became unmanaged reconciliation authorization")
		}
	}
}

func TestLifecycleReconciliationAuthorizationRetainsIdentityAndValidity(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{AllowWorkflowLifecycleReconciliation: true})
	replacement := liveAuthorizationAuthority(t, Policy{AllowWorkflowLifecycleReconciliation: true, AllowDownloads: true})
	var current atomic.Pointer[Authority]
	current.Store(first)
	var unavailable atomic.Bool
	guard := NewGuard(func() (*Authority, error) {
		if unavailable.Load() {
			return nil, ErrUnavailable
		}
		return current.Load(), nil
	})
	grant, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		t.Fatal("initial reconciliation grant is unavailable")
	}
	identical := *first
	current.Store(&identical)
	if grant.Check() != nil {
		t.Fatal("equivalent authenticated authority lost its identity")
	}
	current.Store(replacement)
	if !errors.Is(grant.Check(), ErrDenied) {
		t.Fatal("replacement signed payload reused a previous reconciliation grant")
	}
	fresh, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil || fresh.Check() != nil {
		t.Fatal("fresh permitted replacement could not authorize a new review")
	}
	changedKey := *replacement
	changedKey.verified.KeyID = "different-source-key"
	current.Store(&changedKey)
	if !errors.Is(fresh.Check(), ErrDenied) {
		t.Fatal("changed trust key reused retained reconciliation authorization")
	}
	current.Store(nil)
	if !errors.Is(grant.Check(), ErrDenied) {
		t.Fatal("managed reconciliation grant survived policy removal")
	}
	unmanaged, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		t.Fatal("explicit unmanaged source is unavailable")
	}
	current.Store(first)
	if !errors.Is(unmanaged.Check(), ErrDenied) {
		t.Fatal("unmanaged reconciliation grant survived enrollment")
	}
	unavailable.Store(true)
	if !errors.Is(grant.Check(), ErrUnavailable) {
		t.Fatal("source failure retained reconciliation authorization")
	}
	unavailable.Store(false)
	current.Store(first)
	// Exercise the retained deadline without changing any production clock or
	// machine source. Signed-envelope expiry is separately checked above.
	grant.expiresAt = time.Now().Add(-time.Millisecond)
	if !errors.Is(grant.Check(), ErrDenied) {
		t.Fatal("expired retained reconciliation grant remained usable")
	}
}

func TestLifecycleReconciliationAuthorizationRechecksBeforeReturn(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{AllowWorkflowLifecycleReconciliation: true})
	changed := liveAuthorizationAuthority(t, Policy{AllowWorkflowLifecycleReconciliation: true, AllowDiagnostics: true})
	for _, next := range []func() (*Authority, error){
		func() (*Authority, error) { return nil, nil },
		func() (*Authority, error) { return changed, nil },
		func() (*Authority, error) { return nil, ErrUnavailable },
	} {
		reads := 0
		guard := NewGuard(func() (*Authority, error) {
			reads++
			if reads == 1 {
				return first, nil
			}
			return next()
		})
		if grant, err := guard.AuthorizeLifecycleReconciliation(); grant != nil || !IsPolicyError(err) || reads != 2 {
			t.Fatal("source change during reconciliation grant acquisition was accepted")
		}
	}
}

func TestLifecycleReconciliationAuthorizationContextIsTerminal(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{AllowWorkflowLifecycleReconciliation: true})
	changed := liveAuthorizationAuthority(t, Policy{AllowWorkflowLifecycleReconciliation: true, AllowDiagnostics: true})
	var current atomic.Pointer[Authority]
	current.Store(first)
	guard := NewGuard(func() (*Authority, error) { return current.Load(), nil })
	grant, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		t.Fatal("source reconciliation grant is unavailable")
	}
	ctx, stop, err := grant.Context(context.Background())
	if err != nil {
		t.Fatal("reconciliation authorization monitor did not start")
	}
	defer stop()
	current.Store(changed)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), ErrDenied) {
			t.Fatal("reconciliation revocation lost its policy cause")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("reconciliation grant ignored policy replacement")
	}
	current.Store(first)
	if !errors.Is(context.Cause(ctx), ErrDenied) {
		t.Fatal("restored policy revived a revoked reconciliation operation")
	}
	grant, err = guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		t.Fatal("fresh reconciliation authorization is unavailable")
	}
	grant.expiresAt = time.Now().Add(30 * time.Millisecond)
	expiring, cancel, err := grant.Context(context.Background())
	if err != nil {
		t.Fatal("expiring reconciliation authorization did not start")
	}
	defer cancel()
	select {
	case <-expiring.Done():
		if !errors.Is(context.Cause(expiring), ErrDenied) {
			t.Fatal("reconciliation expiry lost its policy cause")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reconciliation expiry did not cancel its retained grant")
	}
}

func TestLifecycleReconciliationReviewBindingIsStableAndNotAGrant(t *testing.T) {
	_, public, private, _ := fixture(t)
	_, otherPublic, otherPrivate, _ := fixture(t)
	now := time.Now().UTC()
	policy := Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), AllowWorkflowLifecycleReconciliation: true}
	authorityFor := func(policy Policy, public ed25519.PublicKey, private ed25519.PrivateKey) *Authority {
		payload, err := json.Marshal(policy)
		if err != nil {
			t.Fatal("review binding policy fixture could not be encoded")
		}
		envelope, err := Sign(payload, private, now)
		if err != nil {
			t.Fatal("review binding policy fixture could not be signed")
		}
		installation, err := PrepareInstallation(envelope, public, now, 0)
		if err != nil {
			t.Fatal("review binding fixture installation could not be prepared")
		}
		authority, err := DecodeInstallation(installation, now)
		if err != nil {
			t.Fatal("review binding fixture authority could not be decoded")
		}
		return authority
	}
	first := authorityFor(policy, public, private)
	changedPolicy := policy
	changedPolicy.AllowDiagnostics = true
	changedPayload := authorityFor(changedPolicy, public, private)
	changedKey := authorityFor(policy, otherPublic, otherPrivate)
	var current atomic.Pointer[Authority]
	current.Store(first)
	var sourceFailure atomic.Bool
	sourceCause := errors.New("PRIVATE_REVIEW_SOURCE_FAILURE")
	guard := NewGuard(func() (*Authority, error) {
		if sourceFailure.Load() {
			return nil, errors.Join(ErrUnavailable, sourceCause)
		}
		return current.Load(), nil
	})
	grant, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		t.Fatal("review binding grant is unavailable")
	}
	binding, err := grant.ReviewBinding()
	if err != nil || !digestPattern.MatchString(binding) || binding == first.verified.KeyID || binding == first.verified.PayloadSHA256 {
		t.Fatal("review binding did not return an opaque canonical digest")
	}
	fresh, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		t.Fatal("equivalent fresh reconciliation grant is unavailable")
	}
	equivalent, err := fresh.ReviewBinding()
	if err != nil || equivalent != binding {
		t.Fatal("equivalent fresh authorization changed stable review material")
	}
	zoneCopy := *fresh
	zoneCopy.expiresAt = zoneCopy.expiresAt.In(time.FixedZone("source-fixture", 5*60*60))
	equivalent, err = zoneCopy.ReviewBinding()
	if err != nil || equivalent != binding {
		t.Fatal("equivalent retained expiry instant changed review identity")
	}
	shorter := *fresh
	shorter.expiresAt = shorter.expiresAt.Add(-time.Minute)
	shortened, err := shorter.ReviewBinding()
	if err != nil || shortened == binding {
		t.Fatal("review material did not bind its retained expiry")
	}
	for _, replacement := range []*Authority{changedPayload, changedKey} {
		current.Store(replacement)
		if value, err := grant.ReviewBinding(); value != "" || !errors.Is(err, ErrDenied) {
			t.Fatal("changed source retained a usable old review binding")
		}
		replacementGrant, err := guard.AuthorizeLifecycleReconciliation()
		if err != nil {
			t.Fatal("fresh changed-authority grant is unavailable")
		}
		value, err := replacementGrant.ReviewBinding()
		if err != nil || !digestPattern.MatchString(value) || value == binding {
			t.Fatal("review binding omitted a signed payload or key identity change")
		}
	}
	current.Store(nil)
	if value, err := grant.ReviewBinding(); value != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("removed authority retained a managed review binding")
	}
	unmanaged, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		t.Fatal("unmanaged review binding grant is unavailable")
	}
	unmanagedBinding, err := unmanaged.ReviewBinding()
	if err != nil || !digestPattern.MatchString(unmanagedBinding) || unmanagedBinding == binding {
		t.Fatal("managed and unmanaged review identities were conflated")
	}
	again, err := guard.AuthorizeLifecycleReconciliation()
	if err != nil {
		t.Fatal("second unmanaged grant is unavailable")
	}
	if value, err := again.ReviewBinding(); err != nil || value != unmanagedBinding {
		t.Fatal("stable unmanaged identity changed review material")
	}
	current.Store(first)
	if value, err := unmanaged.ReviewBinding(); value != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("new enrollment retained an unmanaged review binding")
	}
	sourceFailure.Store(true)
	if value, err := grant.ReviewBinding(); value != "" || !errors.Is(err, ErrUnavailable) || !errors.Is(err, sourceCause) {
		t.Fatal("failed source returned a review binding or erased its cause")
	}
	sourceFailure.Store(false)
	expired := *grant
	expired.expiresAt = time.Now().Add(-time.Millisecond)
	if value, err := expired.ReviewBinding(); value != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("expired authorization exposed usable review material")
	}
	var missing *Authorization
	if value, err := missing.ReviewBinding(); value != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing authorization exposed review material")
	}
	// The digest cannot be passed as authority, and the permitted operation is
	// still independently refused when only another permission is granted.
	current.Store(authorityFor(Policy{SchemaVersion: 1, Revision: 2, IssuedAt: policy.IssuedAt, ExpiresAt: policy.ExpiresAt, AllowWorkflowHistoryRetirement: true}, public, private))
	if next, err := guard.AuthorizeLifecycleReconciliation(); next != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("review identity or retirement permission substituted for reconciliation authorization")
	}
}
