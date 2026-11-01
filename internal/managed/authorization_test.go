package managed

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorizationIdentityAndRemoval(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{})
	changed := liveAuthorizationAuthority(t, Policy{AllowDiagnostics: true})
	var current atomic.Pointer[Authority]
	current.Store(first)
	var unavailable atomic.Bool
	g := NewGuard(func() (*Authority, error) {
		if unavailable.Load() {
			return nil, errors.New("source access denied")
		}
		return current.Load(), nil
	})
	authorization := newAuthorization(g, first)
	if err := authorization.Check(); err != nil {
		t.Fatal(err)
	}
	// A fresh decode of identical signed data retains the same identity.
	copy := *first
	current.Store(&copy)
	if err := authorization.Check(); err != nil {
		t.Fatal(err)
	}
	current.Store(changed)
	if !errors.Is(authorization.Check(), ErrDenied) {
		t.Fatal("changed payload accepted")
	}
	copy = *first
	copy.verified.KeyID = "replacement-key"
	current.Store(&copy)
	if !errors.Is(authorization.Check(), ErrDenied) {
		t.Fatal("changed key accepted")
	}
	current.Store(nil)
	if !errors.Is(authorization.Check(), ErrDenied) {
		t.Fatal("source removal accepted")
	}
	unmanaged := newAuthorization(g, nil)
	if err := unmanaged.Check(); err != nil {
		t.Fatal(err)
	}
	current.Store(first)
	if !errors.Is(unmanaged.Check(), ErrDenied) {
		t.Fatal("unmanaged session survived enrollment")
	}
	unavailable.Store(true)
	if !errors.Is(authorization.Check(), ErrUnavailable) {
		t.Fatal("source failure accepted")
	}
	if _, _, err := authorization.Context(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("monitor started with inaccessible source", err)
	}
	var missing *Authorization
	if !errors.Is(missing.Check(), ErrUnavailable) {
		t.Fatal("missing authorization accepted")
	}
}

func TestAuthorizationMonitorExpiryAndCancellation(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{})
	g := NewGuard(func() (*Authority, error) { return first, nil })
	authorization := newAuthorization(g, first)
	// Only the timer's retained deadline is shortened, without waiting for a
	// production-size policy validity window or replacing the process clock.
	authorization.expiresAt = time.Now().Add(40 * time.Millisecond)
	ctx, cancel, err := authorization.Context(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), ErrDenied) {
			t.Fatal(context.Cause(ctx))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expiry did not cancel authorization")
	}
	ctx, cancel, err = newAuthorization(g, first).Context(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatal("owner cancellation lost")
	}
}

func TestAuthorizationMonitorSourceFailureIsTerminal(t *testing.T) {
	first := liveAuthorizationAuthority(t, Policy{})
	var broken atomic.Bool
	g := NewGuard(func() (*Authority, error) {
		if broken.Load() {
			return nil, ErrUnavailable
		}
		return first, nil
	})
	ctx, cancel, err := newAuthorization(g, first).Context(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	broken.Store(true)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), ErrUnavailable) {
			t.Fatal(context.Cause(ctx))
		}
	case <-time.After(4 * time.Second):
		t.Fatal("source failure did not cancel authorization")
	}
	broken.Store(false)
	if !errors.Is(context.Cause(ctx), ErrUnavailable) {
		t.Fatal("repaired source resurrected session")
	}
}

func liveAuthorizationAuthority(t *testing.T, p Policy) *Authority {
	t.Helper()
	_, public, private, _ := fixture(t)
	now := time.Now().UTC()
	p.SchemaVersion, p.Revision = 1, 1
	p.IssuedAt, p.ExpiresAt = now.Add(-time.Minute), now.Add(time.Hour)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(data, private, now)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := PrepareInstallation(envelope, public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := DecodeInstallation(installation, now)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
