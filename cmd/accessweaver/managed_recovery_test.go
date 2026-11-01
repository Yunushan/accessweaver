package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
)

func TestManagedRecoveryOfflineSignReviewAndExclusiveOutput(t *testing.T) {
	folder := t.TempDir()
	root := filepath.Join(folder, "must-not-create-user-state")
	t.Setenv("ACCESSWEAVER_HOME", root)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(folder, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p := managed.Policy{SchemaVersion: 1, Revision: 8, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	next, err := managed.Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	nextPath := filepath.Join(folder, "next.json")
	if err := os.WriteFile(nextPath, next, 0600); err != nil {
		t.Fatal(err)
	}
	priorPath := filepath.Join(folder, "source.bin")
	if err := os.WriteFile(priorPath, []byte("\xef\xbb\xbfdamaged source\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	recoveryPath := filepath.Join(folder, "recovery.json")
	args := []string{"sign-recovery", nextPath, "--previous-source", priorPath, "--minimum-revision", "7", "--private-key", keyPath, "--valid-for", "1h", "--out", recoveryPath}
	if out, err := captureManagedCommand(t, args); err != nil || len(out) != 0 {
		t.Fatal("offline recovery signing failed", string(out), err)
	}
	if _, err := captureManagedCommand(t, args); err == nil {
		t.Fatal("existing recovery approval overwritten")
	}
	args[len(args)-1] = keyPath
	if _, err := captureManagedCommand(t, args); err == nil {
		t.Fatal("signing key overwritten")
	}
	if got, err := os.ReadFile(keyPath); err != nil || string(got) != string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})) {
		t.Fatal("private key changed", err)
	}
	verify := []string{"verify-recovery", recoveryPath, "--previous-source", priorPath, "--public-key", base64.StdEncoding.EncodeToString(public), "--minimum-revision", "7"}
	out, err := captureManagedCommand(t, verify)
	if err != nil {
		t.Fatal(err)
	}
	var review managed.RecoveryReview
	if err := json.Unmarshal(out, &review); err != nil || !review.SignatureValid || review.RuntimeEnforced || review.PreviousAuthenticated || review.Next.Policy.Revision != 8 {
		t.Fatal("invalid offline review", string(out), err)
	}
	if err := os.WriteFile(priorPath, []byte("damaged source\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureManagedCommand(t, verify); err == nil {
		t.Fatal("source BOM/line-ending changes were normalized away")
	}

	if err := os.WriteFile(priorPath, []byte("\xef\xbb\xbfdamaged source\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	verify[len(verify)-1] = "6"
	if _, err := captureManagedCommand(t, verify); err == nil {
		t.Fatal("unreviewed floor accepted")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("offline commands created user data", err)
	}
	for _, command := range []string{"export-source", "sign-recovery", "verify-recovery", "recover"} {
		if _, err := captureManagedCommand(t, []string{command}); err == nil {
			t.Fatal("missing recovery arguments accepted", command)
		}
	}
}

func TestManagedMutationPrintsKnownPublicationDespiteError(t *testing.T) {
	for _, committed := range []bool{false, true} {
		output, err := os.CreateTemp(t.TempDir(), "stdout")
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = output
		failure := errors.New("post-publication sync failed")
		err = printManagedMutation(managed.InstallResult{Operation: "recover", Committed: committed}, failure)
		os.Stdout = old
		if !errors.Is(err, failure) {
			output.Close()
			t.Fatal("operation error concealed", err)
		}
		if _, err := output.Seek(0, 0); err != nil {
			output.Close()
			t.Fatal(err)
		}
		data, err := io.ReadAll(output)
		output.Close()
		if err != nil {
			t.Fatal(err)
		}
		if committed && !strings.Contains(string(data), `"committed": true`) || !committed && len(data) > 0 {
			t.Fatalf("incorrect publication outcome %q", data)
		}
	}
}
