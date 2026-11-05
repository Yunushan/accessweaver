//go:build windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/nativepath"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/servicehost"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

const nativePolicyTestKey = `SOFTWARE\Policies\AccessWeaver`

var nativePolicyDLL = syscall.NewLazyDLL("advapi32.dll")

// This branch exists only in the test binary copied as an inert approved engine.
// The production executable has no fixture mode or environment bypass.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ordinaryWorkerArgument {
		os.Exit(runOrdinaryWindowsWorker(os.Args[2:]))
	}
	if os.Getenv("ACCESSWEAVER_MANAGED_ENGINE_FIXTURE") == "1" {
		fmt.Println("approved inert policy fixture")
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func nativeTestDescriptor(t *testing.T, sddl string) unsafe.Pointer {
	t.Helper()
	text, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor unsafe.Pointer
	ok, _, callErr := nativePolicyDLL.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW").Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		t.Fatal(callErr)
	}
	t.Cleanup(func() { syscall.LocalFree(syscall.Handle(uintptr(descriptor))) })
	return descriptor
}
func nativeTestProtectFile(t *testing.T, path string, descriptor unsafe.Pointer) {
	t.Helper()
	var owner, acl unsafe.Pointer
	var present, defaulted int32
	ok, _, err := nativePolicyDLL.NewProc("GetSecurityDescriptorOwner").Call(uintptr(descriptor), uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 {
		t.Fatal(err)
	}
	ok, _, err = nativePolicyDLL.NewProc("GetSecurityDescriptorDacl").Call(uintptr(descriptor), uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&acl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present == 0 || acl == nil {
		t.Fatal("test descriptor lacks DACL", err)
	}
	name, _ := syscall.UTF16PtrFromString(path)
	code, _, _ := nativePolicyDLL.NewProc("SetNamedSecurityInfoW").Call(uintptr(unsafe.Pointer(name)), 1, 0x80000005, uintptr(owner), 0, uintptr(acl), 0)
	if code != 0 {
		t.Fatal(syscall.Errno(code))
	}
}
func nativeTestSetInstallation(t *testing.T, key syscall.Handle, data []byte) {
	t.Helper()
	value, _ := syscall.UTF16PtrFromString("Installation")
	code, _, _ := nativePolicyDLL.NewProc("RegSetValueExW").Call(uintptr(key), uintptr(unsafe.Pointer(value)), 0, syscall.REG_BINARY, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	if code != 0 {
		t.Fatal(syscall.Errno(code))
	}
}

// Only the guarded fixture simulates elapsed time by replacing an entire pair.
// Ordinary native changes use the production transaction, never this writer.
func nativeTestSetAcceptedInstallation(t *testing.T, key syscall.Handle, source []byte, validAt time.Time) {
	t.Helper()
	if _, err := managed.DecodeInstallation(source, validAt); err != nil {
		t.Fatal(err)
	}
	var installation managed.Installation
	if err := json.Unmarshal(source, &installation); err != nil {
		t.Fatal(err)
	}
	installation.SchemaVersion = 2
	pairedSource, err := json.MarshalIndent(installation, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pairedSource = append(pairedSource, 10)
	record, err := json.Marshal(map[string]any{"schemaVersion": 1, "installation": base64.StdEncoding.EncodeToString(pairedSource)})
	if err != nil {
		t.Fatal(err)
	}
	nativeTestSetInstallation(t, key, pairedSource)
	value, _ := syscall.UTF16PtrFromString("Acceptance")
	code, _, _ := nativePolicyDLL.NewProc("RegSetValueExW").Call(uintptr(key), uintptr(unsafe.Pointer(value)), 0, syscall.REG_BINARY, uintptr(unsafe.Pointer(&record[0])), uintptr(len(record)))
	if code != 0 {
		t.Fatal(syscall.Errno(code))
	}
}

// Never enable this on a desktop or self-hosted runner. The workflow invokes it
// only in its disposable GitHub-hosted Windows VM, after ordinary verification.
func TestDisposableManagedPolicyNative(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_POLICY_TEST") != "1" {
		t.Skip("disposable GitHub-hosted Windows VM only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Fatal("refusing native policy mutation outside the declared hosted Windows job")
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	var elevated, size uint32
	if err := syscall.GetTokenInformation(token, 20, (*byte)(unsafe.Pointer(&elevated)), 4, &size); err != nil || elevated == 0 {
		t.Fatal("disposable native test requires an administrative runner", err)
	}
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := user.User.Sid.String()
	if err != nil || sid == "S-1-5-18" {
		t.Fatal("test requires a non-SYSTEM administrator so the limited-token probe is meaningful", err)
	}
	name, _ := syscall.UTF16PtrFromString(nativePolicyTestKey)
	var existing syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, name, 0, syscall.KEY_READ|syscall.KEY_WOW64_64KEY, &existing)
	if err == nil {
		syscall.RegCloseKey(existing)
		t.Fatal("refusing to replace preexisting machine policy")
	}
	if !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		t.Fatal("cannot exclude preexisting policy", err)
	}

	environment, err := nativepath.ProcessEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	programs := ""
	for _, item := range environment {
		key, value, _ := strings.Cut(item, "=")
		if strings.EqualFold(key, "ProgramFiles") {
			programs = value
		}
	}
	if programs == "" {
		t.Fatal("no protected Program Files location")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	fixtureRoot := filepath.Join(programs, "AccessWeaverPolicyTest-"+hex.EncodeToString(random))
	directorySD := nativeTestDescriptor(t, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
	attributes := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: uintptr(directorySD)}
	directoryName, _ := syscall.UTF16PtrFromString(fixtureRoot)
	if err := syscall.CreateDirectory(directoryName, &attributes); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Validate the exact created target before any recursive cleanup.
		absolute, err := filepath.Abs(fixtureRoot)
		if err != nil || !strings.EqualFold(filepath.Dir(absolute), filepath.Clean(programs)) || !strings.HasPrefix(filepath.Base(absolute), "AccessWeaverPolicyTest-") {
			t.Error("refusing unsafe fixture cleanup", err)
			return
		}
		if err := os.RemoveAll(absolute); err != nil {
			t.Error("fixture cleanup", err)
		}
	})
	payload := filepath.Join(fixtureRoot, "payload")
	payloadName, _ := syscall.UTF16PtrFromString(payload)
	if err := syscall.CreateDirectory(payloadName, &attributes); err != nil {
		t.Fatal(err)
	}
	enginePath := filepath.Join(payload, "ciadpi.exe")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enginePath, binary, 0700); err != nil {
		t.Fatal(err)
	}
	nativeTestProtectFile(t, enginePath, directorySD)
	digest := sha256.Sum256(binary)
	binaryHash := hex.EncodeToString(digest[:])
	root := t.TempDir()
	store, err := profile.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	p := profile.New("managed-native", "Approved fixture", "byedpi")
	p.Binary = enginePath
	p.Probe.Host = "127.0.0.1"
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	inputHash, err := p.ExecutionDigest()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	policy := managed.Policy{SchemaVersion: 1, Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Launches: []managed.LaunchRule{{Engine: p.Engine, InputSHA256: inputHash, BinarySHA256: binaryHash}}}
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
	installResult, err := managed.Install(installed, public)
	if err != nil || !installResult.Committed || installResult.Revision != 1 {
		t.Fatal("initial protected installation failed", installResult, err)
	}
	var key syscall.Handle
	t.Cleanup(func() {
		if key != 0 {
			syscall.RegCloseKey(key)
		}
		code, _, _ := nativePolicyDLL.NewProc("RegDeleteKeyExW").Call(uintptr(syscall.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(name)), syscall.KEY_WOW64_64KEY, 0)
		if code != 0 {
			t.Error("policy cleanup", syscall.Errno(code))
		}
	})
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, name, 0, syscall.KEY_READ|syscall.KEY_SET_VALUE|syscall.KEY_WOW64_64KEY, &key); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.Install(installed, public); err == nil {
		t.Fatal("initial install overwrote existing enrollment")
	}
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid || status.Revision != 1 || status.Enforcement != "partial" {
		t.Fatal("native source did not accept protected policy", status, err)
	}
	if err := managed.NewGuard(nil).Diagnostics(); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("native diagnostic restriction bypassed", err)
	}
	if err := servicehost.Run("must-not-read.json"); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("service-host bypassed native policy", err)
	}
	plan, err := workflow.New(root).Preview(workflow.Request{Action: "dns", DNS: "doh"})
	if err != nil || plan.Ready {
		t.Fatal("unapproved native workflow became ready", err)
	}
	current, err := store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Name = "Must not save"
	if err := store.Save(current); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("native read-only profile policy bypassed", err)
	}
	current, err = store.Get(p.ID)
	if err != nil || current.Name != "Approved fixture" {
		t.Fatal("denied profile write changed state", err)
	}
	t.Setenv("ACCESSWEAVER_MANAGED_ENGINE_FIXTURE", "1")
	manager := engine.NewManager(root)
	t.Cleanup(func() {
		if err := manager.Stop(); err != nil {
			t.Error(err)
		}
	})
	if err := manager.Start(p); err != nil {
		t.Fatal("approved protected engine did not start", err)
	}
	if manager.Snapshot().PID == 0 {
		t.Fatal("approved engine never entered running state")
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := nativeLimitedPolicyProbe(enginePath); err != nil {
		t.Fatal("ordinary-token policy protection failed", err)
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
	if err := manager.Start(p); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("changed executable contents accepted", err)
	}
	// Restore the inert fixture after the tamper rejection, then keep it active
	// while two real native update callers contend for the next revision.
	if err := os.WriteFile(enginePath, binary, 0700); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(p); err != nil {
		t.Fatal(err)
	}
	policy.Revision = 2
	updatedBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	updatedEnvelope, err := managed.Sign(updatedBytes, private, now)
	if err != nil {
		t.Fatal(err)
	}
	// Two independent callers must not both accept the same revision.
	var updating sync.WaitGroup
	outcomes := make(chan error, 2)
	for index := 0; index < 2; index++ {
		updating.Add(1)
		go func() { defer updating.Done(); _, err := managed.Update(updatedEnvelope); outcomes <- err }()
	}
	updating.Wait()
	close(outcomes)
	accepted := 0
	for err := range outcomes {
		if err == nil {
			accepted++
		}
	}
	assertNativePolicyStopped(t, manager, "machine policy changed")
	if accepted != 1 {
		t.Fatalf("concurrent update accepted %d copies of one revision", accepted)
	}
	status, err = managed.MachineStatus()
	if err != nil || status.Revision != 2 {
		t.Fatal("monotonic update lost state", status, err)
	}
	if _, err := managed.Update(envelope); err == nil {
		t.Fatal("older signed policy replayed")
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPolicy := policy
	otherPolicy.Revision = 3
	otherBytes, err := json.Marshal(otherPolicy)
	if err != nil {
		t.Fatal(err)
	}
	otherEnvelope, err := managed.Sign(otherBytes, otherPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.Update(otherEnvelope); err == nil {
		t.Fatal("update replaced the enrolled signing key")
	}
	// Administratively stage an expired fixture to prove supported renewal;
	// it must remain blocked for ordinary runtime operations before renewal.
	policy.IssuedAt = now.Add(-2 * time.Hour)
	policy.ExpiresAt = now.Add(-time.Hour)
	expiredBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	expiredEnvelope, err := managed.Sign(expiredBytes, private, now.Add(-90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	expiredInstallation, err := managed.PrepareInstallation(expiredEnvelope, public, now.Add(-90*time.Minute), 1)
	if err != nil {
		t.Fatal(err)
	}
	nativeTestSetAcceptedInstallation(t, key, expiredInstallation, now.Add(-90*time.Minute))
	if _, err := managed.Current(); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("expired fixture authorized runtime", err)
	}
	policy.Revision = 3
	policy.IssuedAt = now.Add(-time.Minute)
	policy.ExpiresAt = now.Add(time.Hour)
	renewedBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	renewedEnvelope, err := managed.Sign(renewedBytes, private, now)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := managed.Update(renewedEnvelope)
	if err != nil || renewed.PreviousRevision != 2 || renewed.Revision != 3 {
		t.Fatal("expired native policy could not renew", renewed, err)
	}
	installed, err = managed.ExportInstallation()
	if err != nil {
		t.Fatal(err)
	}
	// A direct administrator/MDM write of a degenerate key must also block
	// runtime authority, even though its forged group equation can verify.
	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1
	forgedSignature := make([]byte, ed25519.SignatureSize)
	forgedSignature[0] = 1
	weakEnvelope := managed.Envelope{SchemaVersion: 1, KeyID: managed.KeyID(identity), Payload: base64.StdEncoding.EncodeToString(renewedBytes), Signature: base64.StdEncoding.EncodeToString(forgedSignature)}
	weakInstallation, err := json.Marshal(managed.Installation{SchemaVersion: 1, PublicKey: base64.StdEncoding.EncodeToString(identity), MinimumRevision: 2, Envelope: weakEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	nativeTestSetInstallation(t, key, weakInstallation)
	if _, err := managed.Current(); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("degenerate native trust key authorized runtime", err)
	}
	if err := store.Save(current); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("degenerate native trust key allowed mutation", err)
	}
	nativeTestSetInstallation(t, key, installed)
	if err := manager.Start(p); err != nil {
		t.Fatal(err)
	}
	nativeTestSetInstallation(t, key, []byte(`{"schemaVersion":1,"publicKey":"invalid","minimumRevision":0,"envelope":{}}`))
	assertNativePolicyStopped(t, manager, "policy is unavailable")
	if _, err := managed.Current(); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("invalid installed policy fell back to unmanaged", err)
	}
	if err := store.Save(current); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("invalid policy allowed a mutation", err)
	}
	if _, err := managed.Update(renewedEnvelope); err == nil {
		t.Fatal("invalid prior policy was silently repaired with untrusted state")
	}
	nativeTestSetInstallation(t, key, installed)
	evidence := map[string]any{"sourceCommit": os.Getenv("GITHUB_SHA"), "goVersion": runtime.Version(), "platform": runtime.GOOS, "arch": runtime.GOARCH, "protectedRegistryRead": true, "activeUpdateStopsEngine": true, "invalidSourceStopsEngine": true, "approvedFixtureStarted": true, "initialInstallRefusesReplacement": true, "concurrentRevisionReplayDenied": true, "signingKeySubstitutionDenied": true, "expiredPolicyRenewed": true, "readOnlyProfilesEnforced": true, "unapprovedWorkflowDenied": true, "diagnosticsDenied": true, "serviceHostDenied": true, "limitedTokenCannotMutatePolicyOrEngine": true, "changedEngineHashDenied": true, "invalidPolicyFailsClosed": true, "degenerateTrustKeyFailsClosed": true, "registryCleanupScheduled": true, "productionQualificationComplete": false}
	bytes, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// The test cwd is cmd/accessweaver; keep public evidence at repository build/.
	evidenceDir := filepath.Join("..", "..", "build", "managed-policy-checks")
	if err := os.MkdirAll(evidenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidenceDir, "native-policy.json"), append(bytes, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func nativeLimitedPolicyProbe(enginePath string) error {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_DUPLICATE|syscall.TOKEN_QUERY|syscall.TOKEN_IMPERSONATE, &token); err != nil {
		return err
	}
	defer token.Close()
	admin, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	disabled := struct {
		SID        *syscall.SID
		Attributes uint32
	}{SID: admin}
	var limited syscall.Token
	ok, _, callErr := nativePolicyDLL.NewProc("CreateRestrictedToken").Call(uintptr(token), 1, 1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&limited)))
	if ok == 0 {
		return callErr
	}
	defer limited.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ok, _, callErr = nativePolicyDLL.NewProc("ImpersonateLoggedOnUser").Call(uintptr(limited))
	if ok == 0 {
		return callErr
	}
	defer func() {
		ok, _, _ := nativePolicyDLL.NewProc("RevertToSelf").Call()
		if ok == 0 {
			panic("cannot revert restricted native test token")
		}
	}()
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid {
		return fmt.Errorf("limited token could not read verified policy: %v", err)
	}
	name, _ := syscall.UTF16PtrFromString(nativePolicyTestKey)
	var writable syscall.Handle
	for _, access := range []uint32{syscall.KEY_SET_VALUE, syscall.KEY_CREATE_SUB_KEY, 0x10000, 0x40000, 0x80000} {
		err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, name, 0, access|syscall.KEY_WOW64_64KEY, &writable)
		if err == nil {
			syscall.RegCloseKey(writable)
			return fmt.Errorf("limited token can mutate machine policy with access %#x", access)
		}
		if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return err
		}
	}
	file, err := os.OpenFile(enginePath, os.O_WRONLY, 0)
	if err == nil {
		file.Close()
		return errors.New("limited token can alter approved engine")
	}
	if !os.IsPermission(err) {
		return err
	}
	if _, err := managed.Update([]byte(`{}`)); !errors.Is(err, managed.ErrDenied) {
		return fmt.Errorf("limited token bypassed update administrator check: %v", err)
	}
	recoveryKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := managed.Recover([]byte(`{}`), recoveryKey, 1); !errors.Is(err, managed.ErrDenied) {
		return fmt.Errorf("ordinary user bypassed recovery administrator check: %v", err)
	}
	if _, err := managed.Rotate([]byte(`{}`)); !errors.Is(err, managed.ErrDenied) {
		return fmt.Errorf("limited token bypassed rotation administrator check: %v", err)
	}
	if err := managed.NewGuard(nil).ProfileChanges(); !errors.Is(err, managed.ErrDenied) {
		return fmt.Errorf("limited token bypassed profile restriction: %v", err)
	}
	return nil
}
