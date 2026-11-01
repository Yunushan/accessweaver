//go:build windows

package managed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func requireDisposablePolicyRunner(t *testing.T) {
	t.Helper()
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_POLICY_TEST") != "1" {
		t.Skip("disposable GitHub-hosted Windows VM only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Fatal("refusing registry mutation outside disposable hosted Windows job")
	}
	if err := requirePolicyAdministrator(); err != nil {
		t.Fatal(err)
	}
}

// This test never runs in ordinary local/CI unit tests. The dedicated step uses
// a fresh hosted Windows VM and requires no preexisting policy.
func TestDisposablePolicyTransactionRollback(t *testing.T) {
	requireDisposablePolicyRunner(t)
	if candidatePath := os.Getenv("ACCESSWEAVER_POLICY_TX_ABORT_CANDIDATE"); candidatePath != "" {
		candidate, err := os.ReadFile(candidatePath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeInstallation(candidate, time.Now()); err != nil {
			t.Fatal(err)
		}
		tx, err := beginMachineInstallation(false)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Stage(candidate); err != nil {
			t.Fatal(err)
		}
		// Terminate without Close/Commit or Go test cleanup. The OS must abort
		// the pending registry transaction when process handles disappear.
		os.Stdout.WriteString("candidate staged; abandoning process transaction\n")
		os.Exit(79)
	}
	name, _ := syscall.UTF16PtrFromString(machinePolicyKey)
	var existing syscall.Handle
	err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, name, 0, syscall.KEY_READ|syscall.KEY_WOW64_64KEY, &existing)
	if err == nil {
		syscall.RegCloseKey(existing)
		t.Fatal("refusing to alter preexisting policy")
	}
	if !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload, err := json.Marshal(policy)
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
	// An abandoned initial stage must not expose an empty or partial key.
	tx, err := beginMachineInstallation(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Stage(installed); err != nil {
		tx.Close()
		t.Fatal(err)
	}
	if current, err := Current(); err != nil || current != nil {
		tx.Close()
		t.Fatal("uncommitted installation became visible", err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	if current, err := Current(); err != nil || current != nil {
		t.Fatal("aborted bootstrap left machine policy", err)
	}
	result, err := Install(installed, public)
	if err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	t.Cleanup(func() {
		code, _, _ := securityDLL.NewProc("RegDeleteKeyExW").Call(uintptr(syscall.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(name)), syscall.KEY_WOW64_64KEY, 0)
		if code != 0 {
			t.Error("policy cleanup", syscall.Errno(code))
		}
	})
	policy.Revision = 2
	payload, err = json.Marshal(policy)
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
	tx, err = beginMachineInstallation(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Stage(candidate); err != nil {
		tx.Close()
		t.Fatal(err)
	}
	status, err := MachineStatus()
	if err != nil || status.Revision != 1 {
		tx.Close()
		t.Fatal("pending update replaced committed revision", status, err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	status, err = MachineStatus()
	if err != nil || status.Revision != 1 {
		t.Fatal("aborted update replaced committed policy", status, err)
	}
	candidatePath := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(candidatePath, candidate, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDisposablePolicyTransactionRollback$", "-test.v")
	child.Env = append(os.Environ(), "ACCESSWEAVER_POLICY_TX_ABORT_CANDIDATE="+candidatePath)
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 79 || !bytes.Contains(output, []byte("candidate staged; abandoning process transaction")) {
		t.Fatalf("crash fixture did not reach staged exit: %s %v", output, err)
	}
	status, err = MachineStatus()
	if err != nil || status.Revision != 1 {
		t.Fatal("process exit published uncommitted policy", status, err)
	}
	result, err = Update(envelope)
	if err != nil || result.PreviousRevision != 1 || result.Revision != 2 {
		t.Fatal("aborted transaction prevented next valid update", result, err)
	}
	evidence := map[string]any{"sourceCommit": os.Getenv("GITHUB_SHA"), "goVersion": runtime.Version(), "platform": runtime.GOOS, "arch": runtime.GOARCH, "abandonedBootstrapInvisible": true, "pendingUpdateInvisible": true, "closedTransactionRolledBack": true, "processExitRolledBack": true, "validUpdateAfterAbort": true, "registryCleanupScheduled": true, "productionQualificationComplete": false}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "build", "managed-policy-checks")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "transaction-policy.json"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
