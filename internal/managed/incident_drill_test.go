package managed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// This ordered exercise joins the real signing, accepted-history, transaction
// and live authorization paths. Storage is controlled in memory: this is not a
// native enrollment, certificate revocation, vendor process or endpoint drill.
func TestPolicyIncidentContainmentAndRecoveryDrill(t *testing.T) {
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	oldPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, ed25519.SeedSize))
	newPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{22}, ed25519.SeedSize))
	oldPublic := oldPrivate.Public().(ed25519.PublicKey)
	newPublic := newPrivate.Public().(ed25519.PublicKey)
	signed := func(t *testing.T, revision uint64, permitted bool, key ed25519.PrivateKey) []byte {
		t.Helper()
		policy := Policy{SchemaVersion: 1, Revision: revision, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), AllowDiagnostics: permitted, AllowProfileChanges: permitted}
		payload, err := json.Marshal(policy)
		if err != nil {
			t.Fatal("drill policy encoding failed")
		}
		envelope, err := Sign(payload, key, now)
		if err != nil {
			t.Fatal("drill policy signing failed")
		}
		return envelope
	}
	var mu sync.RWMutex
	var state machineSnapshot
	load := func() (*Authority, error) {
		mu.RLock()
		defer mu.RUnlock()
		authority, _, err := decodeMachineSnapshot(state, time.Now())
		return authority, err
	}
	txForState := func() *fakeInstallationTransaction {
		mu.RLock()
		defer mu.RUnlock()
		return &fakeInstallationTransaction{prior: bytes.Clone(state.source), present: state.present, acceptance: bytes.Clone(state.acceptance), acceptancePresent: state.acceptancePresent}
	}
	publish := func(t *testing.T, tx *fakeInstallationTransaction) {
		t.Helper()
		if len(tx.published) == 0 || len(tx.publishedAcceptance) == 0 || tx.closeCalls != 1 {
			t.Fatal("drill publication was not confirmed")
		}
		mu.Lock()
		defer mu.Unlock()
		state = machineSnapshot{source: bytes.Clone(tx.published), acceptance: bytes.Clone(tx.publishedAcceptance), present: true, acceptancePresent: true}
	}
	refused := func(t *testing.T, tx *fakeInstallationTransaction, result InstallResult, err error) {
		t.Helper()
		if err == nil || result.Committed || tx.published != nil || tx.publishedAcceptance != nil || tx.closeCalls != 1 {
			t.Fatal("unapproved drill transition published")
		}
	}
	step := func(name string, body func(*testing.T)) {
		t.Helper()
		if !t.Run(name, body) {
			t.FailNow()
		}
	}
	guard := NewGuard(load)
	var grant *Authorization
	var operation context.Context
	var cancel context.CancelFunc
	step("baseline-signed-enrollment", func(t *testing.T) {
		tx := txForState()
		installation, err := PrepareInstallation(signed(t, 40, true, oldPrivate), oldPublic, now, 0)
		if err != nil {
			t.Fatal("baseline installation preparation failed")
		}
		result, err := commitInstallation(tx, installation, oldPublic, changeInstall, clock)
		if err != nil || !result.Committed || result.Revision != 40 {
			t.Fatal("baseline enrollment failed")
		}
		publish(t, tx)
		if guard.ProfileChanges() != nil {
			t.Fatal("baseline profile permission unavailable")
		}
		grant, err = guard.AuthorizeDiagnostics()
		if err != nil {
			t.Fatal("baseline diagnostic permission unavailable")
		}
		operation, cancel, err = grant.Context(context.Background())
		if err != nil {
			t.Fatal("baseline owned authorization unavailable")
		}
	})
	defer cancel()
	step("publish-deny-by-default-containment", func(t *testing.T) {
		tx := txForState()
		result, err := commitInstallation(tx, signed(t, 41, false, oldPrivate), nil, changeUpdate, clock)
		if err != nil || !result.Committed || result.Revision != 41 {
			t.Fatal("containment publication failed")
		}
		publish(t, tx)
		if !errors.Is(grant.Check(), ErrDenied) || !errors.Is(guard.Diagnostics(), ErrDenied) || !errors.Is(guard.ProfileChanges(), ErrDenied) {
			t.Fatal("containment retained old permission")
		}
		if _, err := guard.Workflow("dns", string(bytes.Repeat([]byte{'a'}, 64)), nil); !errors.Is(err, ErrDenied) {
			t.Fatal("containment authorized a workflow")
		}
		if err := guard.Launch(LaunchRequest{Engine: "byedpi", InputSHA256: string(bytes.Repeat([]byte{'b'}, 64))}); !errors.Is(err, ErrDenied) {
			t.Fatal("containment authorized a component")
		}
	})
	step("cancel-retained-operation", func(t *testing.T) {
		select {
		case <-operation.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("contained operation did not observe policy change")
		}
		if !errors.Is(context.Cause(operation), ErrDenied) {
			t.Fatal("containment cancellation lost its cause")
		}
	})
	step("reject-older-and-replacement-key-updates", func(t *testing.T) {
		for _, next := range [][]byte{signed(t, 40, true, oldPrivate), signed(t, 42, true, newPrivate)} {
			tx := txForState()
			result, err := commitInstallation(tx, next, nil, changeUpdate, clock)
			refused(t, tx, result, err)
		}
	})
	var damaged []byte
	var retained []byte
	step("damaged-source-stays-enrolled-and-blocked", func(t *testing.T) {
		mu.Lock()
		state.source = []byte("damaged policy incident fixture\n")
		damaged = bytes.Clone(state.source)
		retained = bytes.Clone(state.acceptance)
		mu.Unlock()
		if _, err := load(); err == nil {
			t.Fatal("damaged source became an unmanaged enrollment")
		}
		if guard.Diagnostics() == nil || guard.ProfileChanges() == nil {
			t.Fatal("damaged source restored permissions")
		}
		tx := txForState()
		installation, err := PrepareInstallation(signed(t, 42, true, newPrivate), newPublic, now, 0)
		if err != nil {
			t.Fatal("replacement installation preparation failed")
		}
		result, err := commitInstallation(tx, installation, newPublic, changeInstall, clock)
		refused(t, tx, result, err)
	})
	next := signed(t, 42, true, newPrivate)
	approval, err := SignRecovery(damaged, next, newPrivate, 41, now, time.Hour)
	if err != nil {
		t.Fatal("independently pinned recovery preparation failed")
	}
	step("review-independent-key-source-and-floor", func(t *testing.T) {
		review, err := VerifyRecovery(damaged, approval, newPublic, 41, now)
		if err != nil || !review.SignatureValid || review.RuntimeEnforced || review.Next.Policy.Revision != 42 || review.Next.KeyID != KeyID(newPublic) {
			t.Fatal("recovery review lost independent identity")
		}
		for _, attempt := range []struct {
			source []byte
			key    ed25519.PublicKey
			floor  uint64
		}{
			{damaged, oldPublic, 41}, {damaged, newPublic, 40}, {[]byte("changed fixture"), newPublic, 41},
		} {
			if _, err := VerifyRecovery(attempt.source, approval, attempt.key, attempt.floor, now); err == nil {
				t.Fatal("recovery review accepted a changed independent input")
			}
		}
	})
	step("retained-history-defeats-lowered-external-floor", func(t *testing.T) {
		stale, err := SignRecovery(damaged, signed(t, 41, true, newPrivate), newPrivate, 40, now, time.Hour)
		if err != nil {
			t.Fatal("stale drill approval preparation failed")
		}
		tx := txForState()
		result, err := commitRecovery(tx, stale, newPublic, 40, clock)
		refused(t, tx, result, err)
		if tx.stageCalls != 0 || tx.commitCalls != 0 {
			t.Fatal("retained revision refusal occurred after staging")
		}
	})
	step("failed-publication-preserves-blocked-source", func(t *testing.T) {
		failure := errors.New("fixed drill transaction fault")
		for _, stageFault := range []bool{true, false} {
			tx := txForState()
			if stageFault {
				tx.stageErr = failure
			} else {
				tx.commitErr = failure
			}
			result, err := commitRecovery(tx, approval, newPublic, 41, clock)
			refused(t, tx, result, err)
			if !errors.Is(err, failure) {
				t.Fatal("failed drill transition concealed its cause")
			}
			current := txForState()
			if !bytes.Equal(current.prior, damaged) || !bytes.Equal(current.acceptance, retained) || guard.Diagnostics() == nil {
				t.Fatal("failed recovery changed containment")
			}
		}
	})
	step("approval-expiry-after-staging-aborts", func(t *testing.T) {
		short, err := SignRecovery(damaged, next, newPrivate, 41, now, time.Second)
		if err != nil {
			t.Fatal("short drill approval unavailable")
		}
		tx := txForState()
		calls := 0
		result, err := commitRecovery(tx, short, newPublic, 41, func() time.Time {
			calls++
			if calls > 1 {
				return now.Add(time.Second)
			}
			return now
		})
		refused(t, tx, result, err)
		if tx.stageCalls != 1 || tx.commitCalls != 0 {
			t.Fatal("expired recovery reached publication")
		}
	})
	step("recover-new-key-with-known-cleanup-error", func(t *testing.T) {
		failure := errors.New("fixed drill close fault")
		tx := txForState()
		tx.closeErr = failure
		result, err := commitRecovery(tx, approval, newPublic, 41, clock)
		if !errors.Is(err, failure) || !result.Committed || result.Revision != 42 || result.PreviousRevision != 41 || result.KeyID != KeyID(newPublic) {
			t.Fatal("known recovery publication concealed")
		}
		publish(t, tx)
		current, err := load()
		if err != nil || current.verified.KeyID != KeyID(newPublic) || current.verified.Policy.Revision != 42 {
			t.Fatal("published recovery inspection failed")
		}
	})
	step("reject-recovery-replay-and-former-signer", func(t *testing.T) {
		tx := txForState()
		result, err := commitRecovery(tx, approval, newPublic, 41, clock)
		refused(t, tx, result, err)
		tx = txForState()
		result, err = commitInstallation(tx, signed(t, 43, true, oldPrivate), nil, changeUpdate, clock)
		refused(t, tx, result, err)
	})
	step("fresh-approval-required-after-recovery", func(t *testing.T) {
		if !errors.Is(grant.Check(), ErrDenied) || operation.Err() == nil {
			t.Fatal("recovery revived old work")
		}
		fresh, err := guard.AuthorizeDiagnostics()
		if err != nil || fresh.Check() != nil || guard.ProfileChanges() != nil {
			t.Fatal("fresh recovery authorization unavailable")
		}
		if _, err := guard.Workflow("dns", string(bytes.Repeat([]byte{'a'}, 64)), nil); !errors.Is(err, ErrDenied) {
			t.Fatal("recovery implicitly restored a workflow")
		}
		if err := guard.Launch(LaunchRequest{Engine: "byedpi", InputSHA256: string(bytes.Repeat([]byte{'b'}, 64))}); !errors.Is(err, ErrDenied) {
			t.Fatal("recovery implicitly restored a component")
		}
		ctx, done, err := fresh.Context(context.Background())
		if err != nil || ctx.Err() != nil {
			t.Fatal("fresh recovery operation unavailable")
		}
		done()
	})
}
