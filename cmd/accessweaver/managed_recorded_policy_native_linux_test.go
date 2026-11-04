//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/managed"
)

// A separate source-built hosted fixture exercises the real CLI/native paths.
// It neither executes an installed product nor changes the ordinary-user probe.
func TestDisposableLinuxRecordedPolicyTransactions(t *testing.T) {
	linuxNativeContext(t)
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Fatal("recorded transaction fixture requires hosted root")
	}
	const source = "/etc/accessweaver"
	const lock = "/etc/.accessweaver-policy.lock"
	for _, path := range []string{source, lock} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing preexisting native authority", err)
		}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("/etc", "accessweaver-recorded-policy-test-"+hex.EncodeToString(nonce))
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := os.Lstat(root)
		if err != nil || filepath.Dir(root) != "/etc" || !strings.HasPrefix(filepath.Base(root), "accessweaver-recorded-policy-test-") || !current.IsDir() || !os.SameFile(rootInfo, current) {
			t.Error("refusing changed journal fixture cleanup", err)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	var ownedSource, ownedLock os.FileInfo
	for _, entry := range []struct {
		path      string
		identity  *os.FileInfo
		directory bool
	}{{source, &ownedSource, true}, {lock, &ownedLock, false}} {
		entry := entry
		t.Cleanup(func() {
			current, err := os.Lstat(entry.path)
			if *entry.identity == nil && os.IsNotExist(err) {
				return
			}
			if err != nil || *entry.identity == nil || current.IsDir() != entry.directory || (!entry.directory && !current.Mode().IsRegular()) || !os.SameFile(*entry.identity, current) {
				t.Error("refusing changed native authority cleanup", err)
				return
			}
			if entry.directory {
				err = os.RemoveAll(entry.path)
			} else {
				err = os.Remove(entry.path)
			}
			if err != nil {
				t.Error(err)
			}
		})
	}
	directory := filepath.Join(root, "journal")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := captureAuditExecute(t, []string{"initialize", "--directory", directory})
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := decodeCheckpointObservations(t, data)
	if len(checkpoints) != 1 || checkpoints[0].Sequence != 0 || checkpoints[0].Producer.ActorClass != "administrator" {
		t.Fatal("administrator genesis differs")
	}
	genesis, head := checkpoints[0], checkpoints[0]
	from, to, input := filepath.Join(root, "genesis.json"), filepath.Join(root, "head.json"), filepath.Join(root, "request.json")
	writeRetainedCheckpoint(t, from, genesis)
	writeRetainedCheckpoint(t, to, head)
	type expectedOperation struct{ action, outcome string }
	operations := []expectedOperation{}
	run := func(action string, payload []byte, extra []string, success bool) {
		t.Helper()
		if err := os.WriteFile(input, payload, 0600); err != nil {
			t.Fatal(err)
		}
		args := append([]string{"policy-" + action, "--directory", directory, "--from", from, "--to", to, "--input", input}, extra...)
		observed, err := captureAuditExecute(t, args)
		if success && err != nil {
			t.Fatal("recorded native transaction failed", action, err)
		}
		if !success && !errors.Is(err, audit.ErrRecordedUncertain) {
			t.Fatal("native refusal lost conservative outcome", action, err)
		}
		pair := decodeCheckpointObservations(t, observed)
		if len(pair) != 2 || pair[0].Sequence != head.Sequence+1 || pair[1].Sequence != head.Sequence+2 || pair[0].Producer != genesis.Producer || pair[1].Producer != genesis.Producer || pair[0].StreamID != genesis.StreamID || pair[1].StreamID != genesis.StreamID {
			t.Fatal("recorded native checkpoint continuity differs")
		}
		head = pair[1]
		writeRetainedCheckpoint(t, to, head)
		outcome := "indeterminate"
		if success {
			outcome = "completed"
		}
		operations = append(operations, expectedOperation{"policy." + action, outcome})
		if success {
			ownedSource, err = os.Lstat(source)
			if err != nil || !ownedSource.IsDir() {
				t.Fatal("published source identity unavailable", err)
			}
			current, err := os.Lstat(lock)
			if err != nil || !current.Mode().IsRegular() {
				t.Fatal("coordination identity unavailable", err)
			}
			if ownedLock != nil && !os.SameFile(ownedLock, current) {
				t.Fatal("coordination file replaced")
			}
			ownedLock = current
		}
	}
	snapshot := func() [][]byte {
		t.Helper()
		result := [][]byte{}
		for _, name := range []string{"installation.json", "acceptance.json"} {
			data, err := os.ReadFile(filepath.Join(source, name))
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, data)
		}
		return result
	}
	unchanged := func(before [][]byte) {
		t.Helper()
		after := snapshot()
		for i := range before {
			if !bytes.Equal(before[i], after[i]) {
				t.Fatal("refused recorded operation changed native pair")
			}
		}
	}
	status := func(revision uint64, public ed25519.PublicKey) {
		t.Helper()
		value, err := managed.MachineStatus()
		if err != nil || !value.Valid || value.Revision != revision || value.AcceptedRevision != revision || value.KeyID != managed.KeyID(public) {
			t.Fatal("recorded native authority differs", value, err)
		}
	}
	now := time.Now().UTC()
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(private) })
		return public, private
	}
	public, private := key()
	nextPublic, nextPrivate := key()
	recoveryPublic, recoveryPrivate := key()
	sign := func(revision uint64, private ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := json.Marshal(managed.Policy{SchemaVersion: 1, Revision: revision, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		result, err := managed.Sign(payload, private, now)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	installation, err := managed.PrepareInstallation(sign(10, private), public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	run("install", installation, []string{"--public-key", base64.StdEncoding.EncodeToString(public)}, true)
	status(10, public)
	// Reusing the externally retained genesis must refuse before another intent
	// or native dispatch. Never adopt the journal's current tail as trusted input.
	beforePair := snapshot()
	beforeJournal, err := os.ReadFile(filepath.Join(directory, "events.journal"))
	if err != nil {
		t.Fatal(err)
	}
	writeRetainedCheckpoint(t, to, genesis)
	stale, err := captureAuditExecute(t, []string{"policy-install", "--directory", directory, "--from", from, "--to", to, "--input", input, "--public-key", base64.StdEncoding.EncodeToString(public)})
	if err == nil || len(stale) != 0 {
		t.Fatal("stale native transaction head admitted")
	}
	unchanged(beforePair)
	afterJournal, err := os.ReadFile(filepath.Join(directory, "events.journal"))
	if err != nil || !bytes.Equal(beforeJournal, afterJournal) {
		t.Fatal("stale native transaction changed journal")
	}
	writeRetainedCheckpoint(t, to, head)
	run("update", sign(11, private), nil, true)
	status(11, public)
	prior, err := managed.ExportInstallation()
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := managed.SignRotation(prior, sign(12, nextPrivate), nextPublic, private, now)
	if err != nil {
		t.Fatal(err)
	}
	var corrupt managed.Envelope
	if err := json.Unmarshal(rotation, &corrupt); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(corrupt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatal("rotation signature fixture differs", err)
	}
	signature[0] ^= 1
	corrupt.Signature = base64.StdEncoding.EncodeToString(signature)
	invalidRotation, err := json.Marshal(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	beforePair = snapshot()
	run("rotate", invalidRotation, nil, false)
	unchanged(beforePair)
	status(11, public)
	run("rotate", rotation, nil, true)
	status(12, nextPublic)
	// Damage only the exact fixture-owned source, retaining its independently
	// accepted revision. Recovery needs a separately selected public key/floor.
	current, err := os.Lstat(source)
	if err != nil || !os.SameFile(ownedSource, current) {
		t.Fatal("refusing changed source damage", err)
	}
	damage := []byte("PRIVATE_RECORDED_POLICY_DAMAGED_SOURCE\n")
	if err := os.WriteFile(filepath.Join(source, "installation.json"), damage, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.Current(); !errors.Is(err, managed.ErrUnavailable) {
		t.Fatal("damaged source granted authority", err)
	}
	recovery, err := managed.SignRecovery(damage, sign(13, recoveryPrivate), recoveryPrivate, 12, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	beforePair = snapshot()
	run("recover", recovery, []string{"--public-key", base64.StdEncoding.EncodeToString(public), "--minimum-revision", "12"}, false)
	unchanged(beforePair)
	run("recover", recovery, []string{"--public-key", base64.StdEncoding.EncodeToString(recoveryPublic), "--minimum-revision", "11"}, false)
	unchanged(beforePair)
	run("recover", recovery, []string{"--public-key", base64.StdEncoding.EncodeToString(recoveryPublic), "--minimum-revision", "12"}, true)
	status(13, recoveryPublic)
	beforePair = snapshot()
	run("recover", recovery, []string{"--public-key", base64.StdEncoding.EncodeToString(recoveryPublic), "--minimum-revision", "12"}, false)
	unchanged(beforePair)
	status(13, recoveryPublic)
	exported, err := captureAuditExecute(t, []string{"export", "--directory", directory, "--from", from, "--to", to, "--consent", "metadata-only"})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := audit.VerifySegment(context.Background(), bytes.NewReader(exported), genesis, head)
	if err != nil || verified.Records != 16 || len(operations) != 8 || head.Sequence != 16 {
		t.Fatal("recorded native full segment differs", verified, err)
	}
	lines := bytes.Split(bytes.TrimSuffix(exported, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 16 {
		t.Fatal("recorded native event count differs")
	}
	seen := map[string]bool{}
	for index, wanted := range operations {
		var first, last struct {
			Event audit.Event `json:"event"`
		}
		if err := json.Unmarshal(lines[2*index], &first); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(lines[2*index+1], &last); err != nil {
			t.Fatal(err)
		}
		if first.Event.Action != wanted.action || last.Event.Action != wanted.action || first.Event.Outcome != "intent" || last.Event.Outcome != wanted.outcome || first.Event.OperationID != last.Event.OperationID || seen[first.Event.OperationID] {
			t.Fatal("recorded native action/outcome pairing differs", index)
		}
		seen[first.Event.OperationID] = true
	}
	for _, private := range [][]byte{[]byte(root), damage, installation, rotation, recovery} {
		if bytes.Contains(exported, private) {
			t.Fatal("native authority input escaped audit metadata")
		}
	}
	evidence := map[string]any{"sourceCommit": os.Getenv("GITHUB_SHA"), "platform": "linux", "arch": runtime.GOARCH, "goVersion": runtime.Version(), "recordedNativePolicyInstall": true, "recordedNativePolicyUpdate": true, "recordedNativePolicyRotation": true, "recordedNativeDamagedSourceRecovery": true, "staleHeadPreservesJournalAndNativePair": true, "invalidRotationPreservesNativePair": true, "wrongRecoveryKeyAndFloorPreserveNativePair": true, "recoveryReplayPreservesNativePair": true, "nativeRefusalsRecordedAsIndeterminate": true, "metadataExportActionsAndOutcomesVerified": true, "administratorActorClass": "administrator", "verifiedRecords": 16, "completedTransactions": 4, "indeterminateNativeRefusals": 4, "lastRevision": 13, "independentRecoveryFloor": 12, "cleanupScheduled": true, "productionQualificationComplete": false}
	data, err = json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("build", "managed-policy-checks")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "linux-native-recorded-policy.json"), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(path, "linux-native-recorded-policy.json"), 0644); err != nil {
		t.Fatal(err)
	}
}
