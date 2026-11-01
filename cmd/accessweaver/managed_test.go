package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func captureManagedCommand(t *testing.T, args []string) ([]byte, error) {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	previous := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = previous }()
	callErr := execute(append([]string{"managed"}, args...))
	if _, err := output.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	result, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	return result, callErr
}

func TestManagedCommandsSignReviewWithoutMutatingUserState(t *testing.T) {
	folder := t.TempDir()
	state := filepath.Join(folder, "must-not-create-user-state")
	t.Setenv("ACCESSWEAVER_HOME", state)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(folder, "signer.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	policy := managed.Policy{SchemaVersion: 1, Revision: 7, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Launches: []managed.LaunchRule{}, Workflows: []managed.WorkflowRule{}}
	payload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(folder, "policy.json")
	if err := os.WriteFile(policyPath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureManagedCommand(t, []string{"validate", policyPath}); err != nil {
		t.Fatal(err)
	}
	signed, err := captureManagedCommand(t, []string{"sign", policyPath, "--private-key", keyPath})
	if err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(folder, "signed.json")
	if err := os.WriteFile(envelopePath, signed, 0600); err != nil {
		t.Fatal(err)
	}
	fromFile := filepath.Join(folder, "signed-file.json")
	if out, err := captureManagedCommand(t, []string{"sign", policyPath, "--private-key", keyPath, "--out", fromFile}); err != nil || len(out) != 0 {
		t.Fatal("file signing failed", err)
	}
	written, err := os.ReadFile(fromFile)
	if err != nil || string(written) != string(signed) {
		t.Fatal("file signing differs from stdout encoding", err)
	}
	if _, err := captureManagedCommand(t, []string{"sign", policyPath, "--private-key", keyPath, "--out", fromFile}); err == nil {
		t.Fatal("existing envelope overwritten")
	}
	originalKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := captureManagedCommand(t, []string{"sign", policyPath, "--private-key", keyPath, "--out", keyPath}); err == nil {
		t.Fatal("signing key overwritten")
	}
	retainedKey, err := os.ReadFile(keyPath)
	if err != nil || string(retainedKey) != string(originalKey) {
		t.Fatal("key changed during rejected output", err)
	}
	exported, err := captureManagedCommand(t, []string{"public-key", "--private-key", keyPath})
	if err != nil || strings.TrimSpace(string(exported)) != base64.StdEncoding.EncodeToString(public) {
		t.Fatal("public key export failed", err)
	}
	encodedPublic := base64.StdEncoding.EncodeToString(public)
	installationPath := filepath.Join(folder, "installation.json")
	if out, err := captureManagedCommand(t, []string{"prepare", envelopePath, "--public-key", encodedPublic, "--minimum-revision", "6", "--out", installationPath}); err != nil || len(out) != 0 {
		t.Fatal("installation preparation failed", err)
	}
	installed, err := os.ReadFile(installationPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.DecodeInstallation(installed, time.Now()); err != nil {
		t.Fatal("prepared installation is not verifiable", err)
	}
	if _, err := captureManagedCommand(t, []string{"prepare", envelopePath, "--public-key", encodedPublic, "--minimum-revision", "6", "--out", installationPath}); err == nil {
		t.Fatal("prepared installation overwritten")
	}
	rejectedPath := filepath.Join(folder, "must-not-write.json")
	if _, err := captureManagedCommand(t, []string{"prepare", envelopePath, "--public-key", encodedPublic, "--minimum-revision", "7", "--out", rejectedPath}); err == nil {
		t.Fatal("stale installation exported")
	}
	if _, err := os.Stat(rejectedPath); !os.IsNotExist(err) {
		t.Fatal("failed preparation created output", err)
	}

	reviewed, err := captureManagedCommand(t, []string{"verify", envelopePath, "--public-key", encodedPublic, "--minimum-revision", "6"})
	if err != nil {
		t.Fatal(err)
	}
	var result managed.Verified
	if err := json.Unmarshal(reviewed, &result); err != nil {
		t.Fatal(err)
	}
	if result.Policy.Revision != 7 || !result.SignatureValid || result.RuntimeEnforced {
		t.Fatal("CLI overstated policy enrollment", string(reviewed))
	}
	if strings.Contains(string(signed), base64.StdEncoding.EncodeToString(private)) || strings.Contains(string(reviewed), base64.StdEncoding.EncodeToString(private)) {
		t.Fatal("private signing key leaked")
	}
	rejected, err := captureManagedCommand(t, []string{"verify", envelopePath, "--public-key", encodedPublic, "--minimum-revision", "7"})
	if err == nil || len(rejected) != 0 {
		t.Fatal("stale policy returned a review", err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("managed review wrote application state", err)
	}
	after, err := os.ReadFile(policyPath)
	if err != nil || string(after) != string(payload) {
		t.Fatal("review changed source policy", err)
	}
	after, err = os.ReadFile(envelopePath)
	if err != nil || string(after) != string(signed) {
		t.Fatal("failed review changed envelope", err)
	}
}

func TestManagedCommandsRejectAmbiguousInputsAndKeys(t *testing.T) {
	for _, args := range [][]string{{"validate"}, {"sign", "policy"}, {"verify", "envelope", "--private-key", "key"}, {"verify", "envelope", "--public-key", "key", "--minimum-revision", "-1"}, {"unknown"}, {"install"}, {"install", "file", "--public-key", "invalid"}, {"install", "file", "--minimum-revision", "0"}, {"update"}, {"update", "file", "--public-key", "invalid"}} {
		out, err := captureManagedCommand(t, args)
		if err == nil || len(out) != 0 {
			t.Fatalf("invalid command produced review: %v %v", args, err)
		}
	}
	folder := t.TempDir()
	policyPath := filepath.Join(folder, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(folder, "key.pem")
	if err := os.WriteFile(keyPath, []byte("PRIVATE-KEY-MARKER"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := captureManagedCommand(t, []string{"sign", policyPath, "--private-key", keyPath})
	if err == nil || len(out) != 0 || strings.Contains(err.Error(), "PRIVATE-KEY-MARKER") {
		t.Fatal("invalid key handled unsafely", err)
	}
	if _, err := readManagedFile(folder, 8); err == nil {
		t.Fatal("directory accepted as policy")
	}
	if _, err := readManagedFile(keyPath, 2); err == nil {
		t.Fatal("oversized key accepted")
	}
}

func TestManagedDigestCommandsMatchTypedExecutionInputs(t *testing.T) {
	folder := t.TempDir()
	t.Setenv("ACCESSWEAVER_HOME", filepath.Join(folder, "must-not-create"))
	p := profile.New("approved-profile", "Display name", "byedpi")
	data, err := json.MarshalIndent(p, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(folder, "profile.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := captureManagedCommand(t, []string{"digest-profile", path})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		InputSHA256     string `json:"inputSHA256"`
		RuntimeEnforced bool   `json:"runtimeEnforced"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	expected, err := p.ExecutionDigest()
	if err != nil || result.InputSHA256 != expected || result.RuntimeEnforced {
		t.Fatal("CLI profile approval does not match typed launch inputs", err)
	}
	request := workflow.Request{Action: "dns", DNS: "doh"}
	path = filepath.Join(folder, "request.json")
	if err := os.WriteFile(path, append([]byte{0xef, 0xbb, 0xbf}, []byte(`{ "dns": "doh", "action": "dns" }`)...), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = captureManagedCommand(t, []string{"digest-workflow", path})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	expected, err = request.PolicyDigest()
	if err != nil || result.InputSHA256 != expected || result.RuntimeEnforced {
		t.Fatal("CLI workflow approval does not match typed request inputs", err)
	}
	if err := os.WriteFile(path, []byte(`{"action":"unknown"}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = captureManagedCommand(t, []string{"digest-workflow", path})
	if err == nil || len(out) != 0 {
		t.Fatal("unknown operation received an approval digest")
	}
}

func TestManagedRotationCommandsSignAndReviewWithoutMachineChanges(t *testing.T) {
	folder := t.TempDir()
	state := filepath.Join(folder, "must-not-create")
	t.Setenv("ACCESSWEAVER_HOME", state)
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyPath := filepath.Join(folder, "old.pem")
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p := managed.Policy{SchemaVersion: 1, Revision: 7, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope, err := managed.Sign(payload, oldPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := managed.PrepareInstallation(oldEnvelope, oldPublic, now, 6)
	if err != nil {
		t.Fatal(err)
	}
	priorPath := filepath.Join(folder, "prior.json")
	if err := os.WriteFile(priorPath, prior, 0600); err != nil {
		t.Fatal(err)
	}
	p.Revision = 8
	payload, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	next, err := managed.Sign(payload, newPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	nextPath := filepath.Join(folder, "next.json")
	if err := os.WriteFile(nextPath, next, 0600); err != nil {
		t.Fatal(err)
	}
	rotationPath := filepath.Join(folder, "rotation.json")
	args := []string{"sign-rotation", nextPath, "--previous-installation", priorPath, "--next-public-key", base64.StdEncoding.EncodeToString(newPublic), "--private-key", keyPath, "--out", rotationPath}
	out, err := captureManagedCommand(t, args)
	if err != nil || len(out) != 0 {
		t.Fatal("rotation signing command failed", string(out), err)
	}
	out, err = captureManagedCommand(t, []string{"verify-rotation", rotationPath, "--previous-installation", priorPath, "--public-key", base64.StdEncoding.EncodeToString(oldPublic)})
	if err != nil {
		t.Fatal(err)
	}
	var review managed.RotationReview
	if err := json.Unmarshal(out, &review); err != nil {
		t.Fatal(err)
	}
	if !review.SignatureValid || review.RuntimeEnforced || review.Next.RuntimeEnforced || review.PreviousRevision != 7 || review.Next.Policy.Revision != 8 || review.Next.KeyID != managed.KeyID(newPublic) {
		t.Fatal("misleading CLI rotation review", review)
	}
	out, err = captureManagedCommand(t, []string{"verify-rotation", rotationPath, "--previous-installation", priorPath, "--public-key", base64.StdEncoding.EncodeToString(newPublic)})
	if err == nil || len(out) != 0 {
		t.Fatal("review accepted unpinned previous key", err)
	}
	args[len(args)-1] = keyPath
	out, err = captureManagedCommand(t, args)
	if err == nil || len(out) != 0 {
		t.Fatal("rotation output overwrote a signer key")
	}
	after, err := os.ReadFile(keyPath)
	if err != nil || string(after) != string(keyBytes) {
		t.Fatal("rotation commands changed private key", err)
	}
	after, err = os.ReadFile(priorPath)
	if err != nil || string(after) != string(prior) {
		t.Fatal("rotation commands changed prior installation", err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("offline rotation created user state", err)
	}
	for _, args := range [][]string{{"export-installation"}, {"export-installation", "--out"}, {"sign-rotation"}, {"verify-rotation"}, {"rotate"}, {"rotate", rotationPath, "--public-key", "ignored"}} {
		out, err := captureManagedCommand(t, args)
		if err == nil || len(out) != 0 {
			t.Fatal("ambiguous rotation command accepted", args, err)
		}
	}
}
