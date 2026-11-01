//go:build linux && (amd64 || arm64)

package managed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
)

func TestDisposableLinuxPolicyTransactions(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_LINUX_POLICY_TEST") != "1" {
		t.Skip("disposable hosted Linux runner only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Linux" || os.Geteuid() != 0 {
		t.Fatal("refusing machine changes outside root disposable Linux job")
	}
	if candidatePath := os.Getenv("ACCESSWEAVER_LINUX_ABORT_CANDIDATE"); candidatePath != "" {
		data, err := os.ReadFile(candidatePath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeInstallation(data, time.Now()); err != nil {
			t.Fatal(err)
		}

		parent, err := linuxtrust.OpenRootDirectory(linuxPolicyParent)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := beginLinuxInstallation(parent, os.Getenv("ACCESSWEAVER_LINUX_ABORT_INITIAL") == "1", 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := tx.Read(); err != nil {
			t.Fatal(err)
		}
		if err := tx.Stage(data); err != nil {
			t.Fatal(err)
		}
		fmt.Println("candidate staged; abandoning process before publication")
		os.Exit(79)
	}
	const source = "/etc/accessweaver"
	const coordination = "/etc/.accessweaver-policy.lock"
	if _, err := os.Lstat(coordination); !os.IsNotExist(err) {
		t.Fatal("refusing preexisting coordination file", err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatal("refusing preexisting machine policy", err)
	}
	now := time.Now().UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := PrepareInstallation(envelope, public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	abandon := func(data []byte, initial bool) {
		path := filepath.Join(t.TempDir(), "candidate.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDisposableLinuxPolicyTransactions$", "-test.v")
		child.Env = append(os.Environ(), "ACCESSWEAVER_LINUX_ABORT_CANDIDATE="+path)
		if initial {
			child.Env = append(child.Env, "ACCESSWEAVER_LINUX_ABORT_INITIAL=1")
		}
		output, err := child.CombinedOutput()
		var exit *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 79 || !bytes.Contains(output, []byte("candidate staged; abandoning process before publication")) {
			t.Fatalf("abandonment fixture: %s %v", output, err)
		}
	}
	parent, err := linuxtrust.OpenRootDirectory(linuxPolicyParent)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := beginLinuxInstallation(parent, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	coordinationInfo, err := os.Lstat(coordination)
	if err != nil {
		tx.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		info, err := os.Lstat(coordination)
		if err != nil || !os.SameFile(info, coordinationInfo) || !info.Mode().IsRegular() {
			t.Error("refusing changed coordination cleanup", err)
			return
		}
		if err := os.Remove(coordination); err != nil {
			t.Error(err)
		}
	})
	if err := tx.Stage(installed); err != nil {
		tx.Close()
		t.Fatal(err)
	}
	if a, err := Current(); err != nil || a != nil {
		tx.Close()
		t.Fatal("uncommitted bootstrap exposed partial authority", err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	abandon(installed, true)
	if a, err := Current(); err != nil || a != nil {
		t.Fatal("abandoned bootstrap exposed authority", err)
	}
	result, err := Install(installed, public)
	if err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	orphans, err := filepath.Glob("/etc/.accessweaver-install-*")
	if err != nil || len(orphans) != 0 {
		t.Fatal("abandoned bootstrap not reclaimed", orphans, err)
	}
	owned, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := os.Lstat(source)
		if err != nil || !current.IsDir() || !os.SameFile(owned, current) {
			t.Error("refusing changed source cleanup", err)
			return
		}
		if err := os.RemoveAll(source); err != nil {
			t.Error(err)
		}
	})
	p.Revision = 2
	payload, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := installationTransition(installed, envelope, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	parent, err = linuxtrust.OpenRootDirectory(linuxPolicyParent)
	if err != nil {
		t.Fatal(err)
	}
	tx, err = beginLinuxInstallation(parent, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tx.Read(); err != nil {
		tx.Close()
		t.Fatal(err)
	}
	if err := tx.Stage(candidate); err != nil {
		tx.Close()
		t.Fatal(err)
	}
	if status, err := MachineStatus(); err != nil || status.Revision != 1 {
		tx.Close()
		t.Fatal("pending candidate became visible", status, err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	abandon(candidate, false)
	if status, err := MachineStatus(); err != nil || status.Revision != 1 {
		t.Fatal("process exit published pending policy", status, err)
	}
	result, err = Update(envelope)
	if err != nil || result.Revision != 2 {
		t.Fatal("lock not released after process exit", result, err)
	}
	entries, err := os.ReadDir(source)
	if err != nil || len(entries) != 1 || entries[0].Name() != linuxPolicyFile {
		t.Fatal("abandoned update stage not reclaimed", entries, err)
	}
	previous, err := ExportInstallation()
	if err != nil {
		t.Fatal(err)
	}
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.Revision = 3
	p.AllowDiagnostics = true
	payload, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Sign(payload, nextPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := SignRotation(previous, next, nextPublic, private, now)
	if err != nil {
		t.Fatal(err)
	}
	rotated, _, err := rotationTransition(previous, rotation, now)
	if err != nil {
		t.Fatal(err)
	}
	abandon(rotated, false)
	status, err := MachineStatus()
	if err != nil || status.Revision != 2 || status.KeyID != KeyID(public) {
		t.Fatal("abandoned rotation changed authority", status, err)
	}
	if err := NewGuard(nil).Diagnostics(); !errors.Is(err, ErrDenied) {
		t.Fatal("abandoned rotation changed permission", err)
	}
	result, err = Rotate(rotation)
	if err != nil || !result.Committed || result.KeyID != KeyID(nextPublic) || result.Revision != 3 {
		t.Fatal("native rotation failed", result, err)
	}
	if err := NewGuard(nil).Diagnostics(); err != nil {
		t.Fatal("committed new policy not active", err)
	}
	if _, err := Rotate(rotation); err == nil {
		t.Fatal("rotation replay accepted")
	}
	p.Revision = 4
	payload, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	old, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Update(old); err == nil {
		t.Fatal("retired key authorized update")
	}
	next, err = Sign(payload, nextPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err = Update(next)
	if err != nil || result.Revision != 4 {
		t.Fatal("new key could not update", result, err)
	}
	evidence := map[string]any{"sourceCommit": os.Getenv("GITHUB_SHA"), "platform": "linux", "arch": runtime.GOARCH, "goVersion": runtime.Version(), "initialStagingInvisible": true, "abandonedBootstrapStageReclaimed": true, "pendingUpdateInvisible": true, "processExitDoesNotPublish": true, "abandonedUpdateStageReclaimed": true, "lockReleasedAfterProcessExit": true, "abandonedRotationKeepsOldKey": true, "nativeRotationCommitted": true, "retiredKeyDenied": true, "newKeyUpdateAccepted": true, "rotationReplayDenied": true, "fileAndDirectorySyncCompleted": true, "cleanupScheduled": true, "powerLossQualified": false, "productionQualificationComplete": false}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("build", "managed-policy-checks")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "linux-policy-transactions.json"), append(data, 10), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "linux-policy-transactions.json"), 0644); err != nil {
		t.Fatal(err)
	}
}
