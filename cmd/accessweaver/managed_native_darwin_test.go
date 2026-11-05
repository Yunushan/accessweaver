//go:build darwin && (amd64 || arm64)

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// Test-only inert Mach-O fixture. Production builds have no basename fixture mode.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == darwinOrdinaryWorkerArg {
		os.Exit(ordinaryDarwinWorker())
	}
	if filepath.Base(os.Args[0]) == "ciadpi" {
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if key != "PATH" && key != "LANG" && key != "LC_ALL" && key != "TZ" {
				fmt.Fprintln(os.Stderr, "unexpected managed environment key", key)
				os.Exit(98)
			}
		}
		if os.Getenv("PATH") != "/usr/bin:/bin:/usr/sbin:/sbin" {
			os.Exit(99)
		}
		if handled, exitCode := ordinaryDarwinInertEngine(); handled {
			os.Exit(exitCode)
		}
		fmt.Println("inert managed Darwin fixture ready")
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func darwinNativeContext(t *testing.T) {
	t.Helper()
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST") != "1" {
		t.Skip("disposable GitHub-hosted Darwin runner only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("refusing machine policy mutation outside declared hosted Darwin job")
	}
}
func setDarwinFixtureACL(t *testing.T, path string, mutation bool) {
	t.Helper()
	// Only this test's root-owned source/fixture is mutated on a fresh hosted Mac.
	rights := "everyone allow read,readattr,readextattr,readsecurity"
	if mutation {
		rights = "everyone allow read,write,readattr,readextattr,readsecurity"
	}
	for _, args := range [][]string{{"-N", path}, {"+a", rights, path}} {
		command := exec.Command("/bin/chmod", args...)
		command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("owned ACL fixture: %s %v", output, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("ACL fixture changed the protected POSIX mode", err)
	}
}
func TestDisposableDarwinManagedPolicyNative(t *testing.T) {
	darwinNativeContext(t)
	if os.Getenv("ACCESSWEAVER_DARWIN_POLICY_PROBE") == "1" {
		darwinOrdinaryPolicyProbe(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("native policy test requires root only on the disposable runner")
	}
	const policyDir = "/Library/Preferences/AccessWeaver"
	const coordination = "/Library/Preferences/.accessweaver-policy.lock"
	if _, err := os.Lstat(coordination); !os.IsNotExist(err) {
		t.Fatal("refusing preexisting coordination file", err)
	}
	if _, err := os.Lstat(policyDir); !os.IsNotExist(err) {
		t.Fatal("refusing preexisting machine policy", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	fixtureRoot := filepath.Join("/Library/Preferences", "accessweaver-policy-test-"+hex.EncodeToString(nonce))
	if err := os.Mkdir(fixtureRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixtureRoot, 0755); err != nil {
		t.Fatal(err)
	}
	fixtureInfo, err := os.Lstat(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		absolute, err := filepath.Abs(fixtureRoot)
		current, statErr := os.Lstat(fixtureRoot)
		if err != nil || statErr != nil || filepath.Dir(absolute) != "/Library/Preferences" || !strings.HasPrefix(filepath.Base(absolute), "accessweaver-policy-test-") || !os.SameFile(fixtureInfo, current) || !current.IsDir() {
			t.Error("refusing unsafe fixture cleanup", err, statErr)
			return
		}
		if err := os.RemoveAll(absolute); err != nil {
			t.Error(err)
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	payloadDir := filepath.Join(fixtureRoot, "Approved.app", "Contents", "MacOS")
	if err := os.MkdirAll(payloadDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(payloadDir, 0755); err != nil {
		t.Fatal(err)
	}
	enginePath := filepath.Join(payloadDir, "ciadpi")
	probePath := filepath.Join(payloadDir, "policy-probe")
	for _, path := range []string{enginePath, probePath} {
		if err := os.WriteFile(path, contents, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	p := profile.New("darwin-native", "Approved Darwin fixture", "byedpi")
	p.Binary = enginePath
	p.Probe.Host = "127.0.0.1"
	root := t.TempDir()
	store, err := profile.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	inputHash, err := p.ExecutionDigest()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(contents)
	now := time.Now().UTC()
	policy := managed.Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Launches: []managed.LaunchRule{{Engine: p.Engine, InputSHA256: inputHash, BinarySHA256: hex.EncodeToString(hash[:])}}}
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := managed.Sign(policyBytes, private, now)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := managed.PrepareInstallation(envelope, public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	installationPath := filepath.Join(t.TempDir(), "installation.json")
	if err := os.WriteFile(installationPath, installed, 0600); err != nil {
		t.Fatal(err)
	}
	installedOutput, err := captureManagedCommand(t, []string{"install", installationPath, "--public-key", base64.StdEncoding.EncodeToString(public)})
	var result managed.InstallResult
	if err == nil {
		err = json.Unmarshal(installedOutput, &result)
	}
	if err != nil || !result.Committed {
		t.Fatal("native initial install", result, err)
	}
	coordinationInfo, err := os.Lstat(coordination)
	if err != nil {
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
	owned, err := os.Lstat(policyDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := os.Lstat(policyDir)
		if err != nil || !current.IsDir() || !os.SameFile(owned, current) {
			t.Error("refusing to remove changed policy directory", err)
			return
		}
		if err := os.RemoveAll(policyDir); err != nil {
			t.Error(err)
		}
	})
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid || status.KeyID != managed.KeyID(public) || status.Revision != 1 {
		t.Fatal("native source rejected protected policy", status, err)
	}
	if _, err := managed.Install(installed, public); err == nil {
		t.Fatal("bootstrap replaced enrolled directory")
	}
	if err := managed.NewGuard(nil).Diagnostics(); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("diagnostic restriction bypassed", err)
	}
	changed := p
	changed.Name = "must not save"
	if err := store.Save(changed); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("read-only profile policy bypassed", err)
	}
	profileBytes, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(payloadDir, "profile.json")
	if err := os.WriteFile(profilePath, profileBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(profilePath, 0644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policyDir, "installation.json")
	setDarwinFixtureACL(t, policyPath, false)
	if status, err := managed.MachineStatus(); err != nil || !status.Valid {
		t.Fatal("explicit read-only ACL was refused", status, err)
	}
	runProbe := func(mode string, afterReady ...func()) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, probePath, "-test.run=^TestDisposableDarwinManagedPolicyNative$", "-test.v")
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		child.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR=/tmp", "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "RUNNER_OS=macOS", "ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST=1", "ACCESSWEAVER_DARWIN_POLICY_PROBE=1", "ACCESSWEAVER_DARWIN_POLICY_PROFILE=" + profilePath, "ACCESSWEAVER_DARWIN_POLICY_EXPECT=" + mode}
		if len(afterReady) == 0 {
			output, err := child.CombinedOutput()
			if err != nil || ctx.Err() != nil || !bytes.Contains(output, []byte("ordinary-user policy and launch checks passed")) {
				t.Fatalf("ordinary-user probe: %s %v", output, err)
			}
			return
		}
		pipe, err := child.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		child.Stderr = &stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		ready, passed := false, false
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "ready for active policy revocation" && !ready {
				ready = true
				afterReady[0]()
			}
			if line == "ordinary-user policy and launch checks passed" {
				passed = true
			}
		}
		if err := child.Wait(); err != nil || scanner.Err() != nil || ctx.Err() != nil || !ready || !passed {
			t.Fatal("active ordinary-user probe failed", err, scanner.Err(), stderr.String(), ready, passed)
		}
	}
	frameworks := filepath.Join(filepath.Dir(payloadDir), "Frameworks")
	if err := os.Mkdir(frameworks, 0755); err != nil {
		t.Fatal(err)
	}
	loaderInput := filepath.Join(frameworks, "loader-input.json")
	if err := os.WriteFile(loaderInput, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	runProbe("approved")
	if err := os.Chmod(loaderInput, 0666); err != nil {
		t.Fatal(err)
	}
	runProbe("untrusted-tree")
	if err := os.Chmod(loaderInput, 0644); err != nil {
		t.Fatal(err)
	}
	manager := engine.NewManager(t.TempDir())
	t.Cleanup(func() {
		if err := manager.Stop(); err != nil {
			t.Error(err)
		}
	})
	if err := manager.Start(p); err != nil {
		t.Fatal(err)
	}
	setDarwinFixtureACL(t, policyPath, true)
	assertNativePolicyStopped(t, manager, "policy is unavailable")
	if _, err := managed.Current(); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("effective named ACL write accepted", err)
	}
	setDarwinFixtureACL(t, policyPath, false)
	if err := os.Chmod(policyPath, 0644); err != nil {
		t.Fatal(err)
	}
	// A real atomic update must revoke a running ordinary-user child even
	// when the new revision keeps the same launch approval.
	runProbe("revocation", func() {
		policy.Revision = 2
		data, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		next, err := managed.Sign(data, private, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := managed.Update(next); err != nil {
			t.Fatal(err)
		}
		installed, err = managed.ExportInstallation()
		if err != nil {
			t.Fatal(err)
		}
	})
	owned, err = os.Lstat(policyDir)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(enginePath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0}); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runProbe("tampered")
	if err := os.Chmod(policyDir, 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.Current(); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("writable authority directory accepted", err)
	}
	if err := os.Chmod(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.Current(); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("invalid installed value became unmanaged", err)
	}
	if err := os.WriteFile(policyPath, installed, 0644); err != nil {
		t.Fatal(err)
	}
	evidence := map[string]any{"sourceCommit": os.Getenv("GITHUB_SHA"), "platform": "darwin", "arch": runtime.GOARCH, "goVersion": runtime.Version(), "rootOwnedMachineSource": true, "actualCLIEnrollment": true, "ordinaryUserCLIFixedSource": true, "ordinaryUserHTTPProfileMutationDenied": true, "ordinaryUserHTTPDiagnosticsDenied": true, "ordinaryUserHTTPSessionTokenRequired": true, "activeOrdinaryUserUpdateStopsEngine": true, "unsafeSourceStopsEngine": true, "initialReplacementDenied": true, "ordinaryUserCannotWritePolicyOrEngine": true, "ordinaryUserProfileChangesDenied": true, "approvedOrdinaryUserFixtureStarted": true, "callerEnvironmentNotInherited": true, "readOnlyACLAccepted": true, "ACLWriteWithUnchangedModeFailsClosed": true, "changedEngineHashDenied": true, "mutableBundleFrameworksRefused": true, "writableDirectoryFailsClosed": true, "invalidValueFailsClosed": true, "cleanupScheduled": true, "productionQualificationComplete": false}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("build", "managed-policy-checks")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "darwin-native-policy.json"), append(data, 10), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "darwin-native-policy.json"), 0644); err != nil {
		t.Fatal(err)
	}
}
func darwinOrdinaryPolicyProbe(t *testing.T) {
	if os.Geteuid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("probe did not drop effective UID/GID")
	}
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid {
		t.Fatal("ordinary user cannot read protected policy", status, err)
	}
	if file, err := os.Open("/Library/Preferences/.accessweaver-policy.lock"); err == nil {
		file.Close()
		t.Fatal("ordinary user can open the private writer lock")
	} else if !os.IsPermission(err) {
		t.Fatal(err)
	}
	file, err := os.OpenFile("/Library/Preferences/AccessWeaver/installation.json", os.O_WRONLY, 0)
	if err == nil {
		file.Close()
		t.Fatal("ordinary user opened policy for writing")
	}
	if !os.IsPermission(err) {
		t.Fatal(err)
	}
	if _, err := managed.Update([]byte(`{}`)); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("ordinary user can update machine policy", err)
	}
	recoveryKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := managed.Recover([]byte(`{}`), recoveryKey, 1); !errors.Is(err, managed.ErrDenied) {
		t.Fatalf("ordinary user bypassed recovery administrator check: %v", err)
	}
	if _, err := managed.Rotate([]byte(`{}`)); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("ordinary user can rotate machine policy", err)
	}
	// The real CLI parser must resolve the same fixed source as the API/engine.
	statusOutput, statusErr := captureManagedCommand(t, []string{"status"})
	var cliStatus managed.Status
	if err := json.Unmarshal(statusOutput, &cliStatus); statusErr != nil || err != nil || !cliStatus.Valid || !cliStatus.Supported || cliStatus.AcceptedRevision != status.Revision {
		t.Fatal("ordinary-user CLI source differed", statusErr, err, cliStatus)
	}
	data, err := os.ReadFile(os.Getenv("ACCESSWEAVER_DARWIN_POLICY_PROFILE"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(p); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("ordinary-user profile mutation bypassed policy", err)
	}
	// Use the actual loopback server as an ordinary user with its real session
	// token and default native loader. Neither endpoint receives an injected guard.
	apiManager := engine.NewManager(store.Root)
	server, err := api.New(store, apiManager, nil)
	if err != nil {
		t.Fatal(err)
	}
	apiContext, cancelAPI := context.WithCancel(context.Background())
	address, err := server.Serve(apiContext)
	if err != nil {
		cancelAPI()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancelAPI(); server.Wait() })
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	profileBody, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		method, path, token string
		body                []byte
		want                int
	}{
		{"GET", "/api/bootstrap", "", nil, 403},
		{"GET", "/api/bootstrap", server.Token, nil, 200},
		{"PUT", "/api/v1/profiles/" + p.ID, server.Token, profileBody, 403},
		{"POST", "/api/v1/diagnose", server.Token, []byte("{"), 403},
	} {
		req, err := http.NewRequest(request.method, address+request.path, bytes.NewReader(request.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-AccessWeaver-Token", request.token)
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		closeErr := response.Body.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != request.want {
			t.Fatalf("native HTTP %s %s: status=%d body=%s", request.method, request.path, response.StatusCode, body)
		}
		if request.method != "GET" && !bytes.Contains(body, []byte("administrator policy")) {
			t.Fatalf("HTTP mutation failed outside native policy guard: %s", body)
		}
	}
	file, err = os.OpenFile(p.Binary, os.O_WRONLY, 0)
	if err == nil {
		file.Close()
		t.Fatal("ordinary user can change approved executable")
	}
	if !os.IsPermission(err) {
		t.Fatal(err)
	}
	for _, name := range []string{"PATH", "HOME", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "GCONV_PATH", "BASH_ENV", "ENV", "NODE_OPTIONS", "ACCESSWEAVER_HOME"} {
		t.Setenv(name, "untrusted-value")
	}
	manager := engine.NewManager(t.TempDir())
	t.Cleanup(func() {
		if err := manager.Stop(); err != nil {
			t.Error(err)
		}
	})
	err = manager.Start(p)
	if expectation := os.Getenv("ACCESSWEAVER_DARWIN_POLICY_EXPECT"); expectation == "tampered" || expectation == "untrusted-tree" {
		if !errors.Is(err, managed.ErrDenied) || manager.Snapshot().PID != 0 {
			t.Fatal("changed engine contents accepted", err)
		}
	} else {
		if err != nil {
			t.Fatal("approved ordinary-user engine refused", err)
		}
		deadline := time.Now().Add(3 * time.Second)
		seen := false
		for time.Now().Before(deadline) {
			for _, line := range manager.Snapshot().Log {
				if strings.Contains(line, "inert managed Darwin fixture ready") {
					seen = true
				}
			}
			if seen {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !seen {
			t.Fatal("approved Mach-O fixture did not report sanitized environment", manager.Snapshot())
		}
		if os.Getenv("ACCESSWEAVER_DARWIN_POLICY_EXPECT") == "revocation" {
			fmt.Println("ready for active policy revocation")
			assertNativePolicyStopped(t, manager, "machine policy changed")
		} else if err := manager.Stop(); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("ordinary-user policy and launch checks passed")
}
