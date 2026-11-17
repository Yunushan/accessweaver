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

// This is the complete policy shape before the isolated retirement permission.
// It models the prior strict decoder, not execution of a historical binary.
type historyRetirementPriorPolicy struct {
	Downloads           []DownloadRule `json:"downloads,omitempty"`
	SchemaVersion       int            `json:"schemaVersion"`
	Revision            uint64         `json:"revision"`
	IssuedAt            time.Time      `json:"issuedAt"`
	ExpiresAt           time.Time      `json:"expiresAt"`
	AllowDownloads      bool           `json:"allowDownloads"`
	AllowDiagnostics    bool           `json:"allowDiagnostics"`
	AllowProfileChanges bool           `json:"allowProfileChanges"`
	RequireProfileAudit bool           `json:"requireProfileAudit,omitempty"`
	Launches            []LaunchRule   `json:"launches"`
	Workflows           []WorkflowRule `json:"workflows"`
}

func TestHistoryRetirementPolicyPreservesLegacySignedBytes(t *testing.T) {
	payload, public, private, now := fixture(t)
	const legacy = `{"schemaVersion":1,"revision":2,"issuedAt":"2026-11-01T11:00:00Z","expiresAt":"2026-11-01T13:00:00Z","allowDownloads":false,"allowDiagnostics":false,"allowProfileChanges":false,"launches":[],"workflows":[]}`
	if !bytes.Equal(payload, []byte(legacy)) {
		t.Fatal("absent false permission changed legacy policy bytes")
	}
	signed, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(signed, public, now, 0)
	if err != nil || verified.Policy.AllowWorkflowHistoryRetirement {
		t.Fatal("legacy signed policy lost default denial")
	}
	encoded, err := json.Marshal(verified.Policy)
	if err != nil || !bytes.Equal(encoded, payload) {
		t.Fatal("false omitted permission changed legacy policy serialization")
	}
	var prior historyRetirementPriorPolicy
	if err := strictJSON(payload, MaxPolicyBytes, &prior); err != nil {
		t.Fatal("modeled prior schema did not accept the complete legacy payload")
	}
	allowed := bytes.Replace(payload, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"allowWorkflowHistoryRetirement":true`), 1)
	signed, err = Sign(allowed, private, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err = Verify(signed, public, now, 0)
	if err != nil || !verified.Policy.AllowWorkflowHistoryRetirement {
		t.Fatal("signed permission did not survive verification")
	}
	if err := strictJSON(allowed, MaxPolicyBytes, &prior); err == nil {
		t.Fatal("modeled prior strict schema silently ignored the new permission")
	}
	var envelope Envelope
	if json.Unmarshal(signed, &envelope) != nil {
		t.Fatal("source signed envelope unavailable")
	}
	changed := bytes.Replace(allowed, []byte(`"allowWorkflowHistoryRetirement":true`), []byte(`"allowWorkflowHistoryRetirement":false`), 1)
	envelope.Payload = base64.StdEncoding.EncodeToString(changed)
	tampered, _ := json.Marshal(envelope)
	if _, err := Verify(tampered, public, now, 0); err == nil {
		t.Fatal("permission changed without a new signature")
	}
	explicitFalse := bytes.Replace(payload, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"allowWorkflowHistoryRetirement":false`), 1)
	decoded, err := DecodePolicy(explicitFalse, now, 0)
	if err != nil || decoded.AllowWorkflowHistoryRetirement {
		t.Fatal("explicit false permission was not denied")
	}
}

func TestHistoryRetirementPolicyRejectsAmbiguousPermission(t *testing.T) {
	payload, public, private, now := fixture(t)
	for name, field := range map[string]string{
		"null":            `"allowWorkflowHistoryRetirement":null`,
		"string":          `"allowWorkflowHistoryRetirement":"true"`,
		"number":          `"allowWorkflowHistoryRetirement":1`,
		"array":           `"allowWorkflowHistoryRetirement":[]`,
		"object":          `"allowWorkflowHistoryRetirement":{}`,
		"case-alias":      `"AllowWorkflowHistoryRetirement":true`,
		"lowercase-alias": `"allowworkflowhistoryretirement":true`,
		"duplicate":       `"allowWorkflowHistoryRetirement":true,"allowWorkflowHistoryRetirement":false`,
		"case-override":   `"allowWorkflowHistoryRetirement":true,"AllowWorkflowHistoryRetirement":false`,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := bytes.Replace(payload, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,`+field), 1)
			if _, err := Sign(invalid, private, now); err == nil {
				t.Fatal("ambiguous retirement permission was signed")
			}
			external := Envelope{1, KeyID(public), base64.StdEncoding.EncodeToString(invalid), base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(signatureDomain), invalid...)))}
			encoded, err := json.Marshal(external)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(encoded, public, now, 0); err == nil {
				t.Fatal("ambiguous permission from an external signer was accepted")
			}
		})
	}
}

func TestHistoryRetirementAuthorizationIsSeparateAndDefaultDenied(t *testing.T) {
	digest := strings.Repeat("a", 64)
	cases := []Policy{
		{},
		{AllowProfileChanges: true},
		{AllowProfileChanges: true, RequireProfileAudit: true},
		{AllowDiagnostics: true, AllowDownloads: true},
		{Workflows: []WorkflowRule{{Action: "history-retirement", InputSHA256: digest}}},
	}
	for _, policy := range cases {
		authority := liveAuthorizationAuthority(t, policy)
		guard := NewGuard(func() (*Authority, error) { return authority, nil })
		authorization, err := guard.AuthorizeHistoryRetirement()
		if authorization != nil || !errors.Is(err, ErrDenied) {
			t.Fatal("another permission or workflow approval authorized retirement")
		}
	}
	authority := liveAuthorizationAuthority(t, Policy{AllowWorkflowHistoryRetirement: true})
	guard := NewGuard(func() (*Authority, error) { return authority, nil })
	authorization, err := guard.AuthorizeHistoryRetirement()
	if err != nil || authorization == nil || authorization.Check() != nil {
		t.Fatal("explicit current signed permission was denied")
	}
	if !errors.Is(guard.ProfileChanges(), ErrDenied) || !errors.Is(guard.Diagnostics(), ErrDenied) || !errors.Is(guard.Launch(LaunchRequest{}), ErrDenied) || !errors.Is(guard.ServiceHost(), ErrDenied) {
		t.Fatal("retirement permission granted an unrelated action")
	}
	if _, err := guard.Workflow("history-retirement", digest, nil); !errors.Is(err, ErrDenied) {
		t.Fatal("retirement permission added a native workflow action")
	}
	unmanaged := NewGuard(func() (*Authority, error) { return nil, nil })
	if authorization, err := unmanaged.AuthorizeHistoryRetirement(); err != nil || authorization == nil || authorization.Check() != nil {
		t.Fatal("trusted unmanaged guard behavior changed")
	}
	sourceFault := errors.New("source validation failed")
	for _, result := range []*Authority{nil, authority} {
		broken := NewGuard(func() (*Authority, error) { return result, errors.Join(ErrUnavailable, sourceFault) })
		authorization, err := broken.AuthorizeHistoryRetirement()
		if authorization != nil || !errors.Is(err, ErrUnavailable) || !errors.Is(err, sourceFault) {
			t.Fatal("invalid or unavailable authority became unmanaged")
		}
	}
}

func TestHistoryRetirementAuthorizationBindsPolicyAndValidity(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{AllowWorkflowHistoryRetirement: true})
	changed := liveAuthorizationAuthority(t, Policy{AllowWorkflowHistoryRetirement: true, AllowDiagnostics: true})
	var current atomic.Pointer[Authority]
	current.Store(first)
	var unavailable atomic.Bool
	guard := NewGuard(func() (*Authority, error) {
		if unavailable.Load() {
			return nil, ErrUnavailable
		}
		return current.Load(), nil
	})
	authorization, err := guard.AuthorizeHistoryRetirement()
	if err != nil {
		t.Fatal(err)
	}
	copy := *first
	current.Store(&copy)
	if err := authorization.Check(); err != nil {
		t.Fatal("identical decoded authority lost authorization")
	}
	current.Store(changed)
	if !errors.Is(authorization.Check(), ErrDenied) {
		t.Fatal("unchanged permission on a different signed payload reused authorization")
	}
	current.Store(nil)
	if !errors.Is(authorization.Check(), ErrDenied) {
		t.Fatal("managed authorization survived policy removal")
	}
	unmanaged, err := guard.AuthorizeHistoryRetirement()
	if err != nil {
		t.Fatal(err)
	}
	current.Store(first)
	if !errors.Is(unmanaged.Check(), ErrDenied) {
		t.Fatal("unmanaged authorization survived enrollment")
	}
	unavailable.Store(true)
	if !errors.Is(authorization.Check(), ErrUnavailable) {
		t.Fatal("unavailable source reused retained authorization")
	}
	unavailable.Store(false)
	current.Store(first)
	// Shorten only the retained deadline; no production clock or source changes.
	authorization.expiresAt = time.Now().Add(-time.Millisecond)
	if !errors.Is(authorization.Check(), ErrDenied) {
		t.Fatal("expired retained authorization remained usable")
	}
}

func TestHistoryRetirementAuthorizationRechecksBeforeReturning(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{AllowWorkflowHistoryRetirement: true})
	changed := liveAuthorizationAuthority(t, Policy{AllowWorkflowHistoryRetirement: true, AllowDownloads: true})
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
		authorization, err := guard.AuthorizeHistoryRetirement()
		if authorization != nil || !IsPolicyError(err) {
			t.Fatal("authority change during authorization was accepted")
		}
	}
}

func TestHistoryRetirementAuthorizationContextRemainsTerminal(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{AllowWorkflowHistoryRetirement: true})
	changed := liveAuthorizationAuthority(t, Policy{AllowWorkflowHistoryRetirement: true, AllowDiagnostics: true})
	var current atomic.Pointer[Authority]
	current.Store(first)
	guard := NewGuard(func() (*Authority, error) { return current.Load(), nil })
	authorization, err := guard.AuthorizeHistoryRetirement()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel, err := authorization.Context(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	current.Store(changed)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), ErrDenied) {
			t.Fatal("policy change lost its terminal denial")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("policy change did not cancel retained context")
	}
	current.Store(first)
	if !errors.Is(context.Cause(ctx), ErrDenied) {
		t.Fatal("restored policy revived a canceled operation")
	}
	authorization, err = guard.AuthorizeHistoryRetirement()
	if err != nil {
		t.Fatal(err)
	}
	authorization.expiresAt = time.Now().Add(40 * time.Millisecond)
	expiring, stop, err := authorization.Context(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	select {
	case <-expiring.Done():
		if !errors.Is(context.Cause(expiring), ErrDenied) {
			t.Fatal("expiry lost its denial")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expiry did not cancel retained context")
	}
	ended, end := context.WithCancel(context.Background())
	end()
	if _, _, err := authorization.Context(ended); !errors.Is(err, context.Canceled) {
		t.Fatal("ended caller started a new authorization context")
	}
}
