//go:build darwin && (amd64 || arm64)

package managed

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDisposableDarwinPolicyTransactions(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST") != "1" {
		t.Skip("fresh hosted Mac enrollment only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" || os.Geteuid() != 0 {
		t.Fatal("refusing native machine changes outside root disposable hosted Mac")
	}
	source := filepath.Join(darwinPolicyParent, darwinPolicyDirectory)
	coordination := filepath.Join(darwinPolicyParent, darwinPolicyLock)
	for _, path := range []string{source, coordination} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing preexisting native policy object", path, err)
		}
	}
	stages, err := filepath.Glob(filepath.Join(darwinPolicyParent, darwinStagePrefix+"*"))
	if err != nil || len(stages) != 0 {
		t.Fatal("refusing preexisting staging namespace", err)
	}
	now := time.Now().UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	signed := func(key ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := Sign(payload, key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	initial, err := PrepareInstallation(signed(private), public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Install(initial, public); err != nil || !result.Committed {
		t.Fatal("fixed native enrollment failed", result, err)
	}
	owned, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	lockInfo, err := os.Lstat(coordination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := os.Lstat(source)
		if err != nil || !current.IsDir() || !os.SameFile(owned, current) {
			t.Error("refusing changed authority cleanup", err)
			return
		}
		entries, err := os.ReadDir(source)
		if err != nil || len(entries) != 2 {
			t.Error("refusing unexpected authority layout cleanup", err)
			return
		}
		for _, entry := range entries {
			if entry.Name() != darwinPolicyFile && entry.Name() != darwinAcceptanceFile {
				t.Error("refusing unrelated cleanup", entry.Name())
				return
			}
		}
		if err := os.RemoveAll(source); err != nil {
			t.Error(err)
			return
		}
		info, err := os.Lstat(coordination)
		if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, lockInfo) {
			t.Error("refusing changed coordination cleanup", err)
			return
		}
		if err := os.Remove(coordination); err != nil {
			t.Error(err)
		}
	})
	refresh := func() {
		t.Helper()
		var err error
		owned, err = os.Lstat(source)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Install(initial, public); err == nil {
		t.Fatal("bootstrap overwrote existing native authority")
	}
	previous, err := ExportInstallation()
	if err != nil {
		t.Fatal(err)
	}
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.Revision = 2
	p.AllowDiagnostics = true
	rotation, err := SignRotation(previous, signed(nextPrivate), nextPublic, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Rotate(rotation); err != nil || !result.Committed || result.KeyID != KeyID(nextPublic) || result.Revision != 2 {
		t.Fatal("fixed native key rotation failed", result, err)
	}
	refresh()
	if _, err := Rotate(rotation); err == nil {
		t.Fatal("native key rotation replay accepted")
	}
	if err := NewGuard(nil).Diagnostics(); err != nil {
		t.Fatal("rotated policy permission not active", err)
	}
	rollback, err := ExportInstallation()
	if err != nil {
		t.Fatal(err)
	}
	p.Revision = 3
	if _, err := Update(signed(private)); err == nil {
		t.Fatal("retired key authorized native update")
	}
	next := signed(nextPrivate)
	if result, err := Update(next); err != nil || !result.Committed || result.Revision != 3 {
		t.Fatal("new key could not update fixed native policy", result, err)
	}
	refresh()
	mutateSource := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(source, darwinPolicyFile), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	mutateAcceptance := func(data []byte) {
		t.Helper()
		path := filepath.Join(source, darwinAcceptanceFile)
		if data == nil {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	exerciseNativeAcceptance(t, rollback, next, mutateSource, mutateAcceptance)
	// Close-abort is covered here; abrupt process exit and physical power loss
	// remain separate requirements. No abandoned objects are guessed/reclaimed.
	exerciseNativeRecovery(t, 3, mutateSource, func(candidate []byte) {
		parent, err := openDarwinPolicyParent()
		if err != nil {
			t.Fatal(err)
		}
		tx, err := beginDarwinInstallation(parent, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := stageNativePolicyFixture(tx, candidate, time.Now()); err != nil {
			tx.Close()
			t.Fatal(err)
		}
		if err := tx.Close(); err != nil {
			t.Fatal(err)
		}
	})
	refresh()
	status, err := MachineStatus()
	if err != nil || !status.Supported || !status.Valid || status.StorageVersion != 2 || status.AcceptedRevision != 5 || status.Revision != 5 {
		t.Fatal("repaired fixed native pair invalid", status, err)
	}
	report := map[string]any{"sourceCommit": os.Getenv("GITHUB_SHA"), "platform": "darwin", "arch": runtime.GOARCH, "goVersion": runtime.Version(), "rootOwnedFixedMachineSource": true, "nativeKeyRotationCommitted": true, "rotationReplayDenied": true, "retiredKeyDenied": true, "newKeyUpdateAccepted": true, "nativeAcceptedPairPublished": true, "primaryRollbackDenied": true, "missingAcceptanceDenied": true, "corruptAcceptanceDenied": true, "acceptedRecoveryFloorEnforced": true, "damagedSourceRemainsBlocked": true, "emptySourceRemainsBlocked": true, "nativeEmptySourceRecoveryCommitted": true, "emptySourceRecoveryReplayDenied": true, "closedRecoveryStageInvisible": true, "nativeSignedRecoveryCommitted": true, "recoveryReplayDenied": true, "recoveryKeyAndFloorMismatchDenied": true, "fileAndDirectoryFullSyncCompleted": true, "automaticAbandonedStageReclamationQualified": false, "processExitQualificationComplete": false, "powerLossQualified": false, "cleanupScheduled": true, "productionQualificationComplete": false}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("build", "managed-policy-checks")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "darwin-policy-transactions.json"), append(data, 10), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Current(); errors.Is(err, ErrUnavailable) {
		t.Fatal("successful repair left authority blocked", err)
	}
}
