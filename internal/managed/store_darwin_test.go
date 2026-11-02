//go:build darwin && (amd64 || arm64)

package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func darwinFixtureTransaction(t *testing.T, parent string, initial bool) *darwinInstallationTransaction {
	t.Helper()
	dir, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := beginDarwinInstallation(dir, initial, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	})
	return tx
}
func darwinFixtureInstall(t *testing.T, parent string, data []byte, now time.Time) []byte {
	t.Helper()
	tx := darwinFixtureTransaction(t, parent, true)
	installed, err := parseInstallation(data)
	if err != nil {
		t.Fatal(err)
	}
	key, err := PublicKey(installed.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := commitInstallation(tx, data, key, changeInstall, func() time.Time { return now })
	if err != nil || !result.Committed {
		t.Fatal("temporary fixture install", result, err)
	}
	stored, err := os.ReadFile(filepath.Join(parent, darwinPolicyDirectory, darwinPolicyFile))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func darwinStoredPair(t *testing.T, parent string) machineSnapshot {
	t.Helper()
	dir, err := os.Open(filepath.Join(parent, darwinPolicyDirectory))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, readErr := readDarwinPolicyPair(dir, uint32(os.Geteuid()))
	if err := errors.Join(readErr, dir.Close()); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestDarwinNativePairInstallUpdateAndRollback(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	darwinFixtureInstall(t, parent, prior, now)
	original := darwinStoredPair(t, parent)
	tx := darwinFixtureTransaction(t, parent, false)
	result, err := commitInstallation(tx, next, nil, changeUpdate, func() time.Time { return now })
	if err != nil || !result.Committed {
		t.Fatal("paired update failed", result, err)
	}
	updated := darwinStoredPair(t, parent)
	authority, history, err := decodeMachineSnapshot(updated, now)
	if err != nil || history == nil || history.revision != 3 || authority.verified.Policy.Revision != 3 {
		t.Fatal("published pair invalid", err)
	}
	document, err := parseInstallation(updated.source)
	if err != nil || document.SchemaVersion != 2 {
		t.Fatal("native paired marker missing", err)
	}
	if err := os.WriteFile(filepath.Join(parent, darwinPolicyDirectory, darwinPolicyFile), original.source, 0644); err != nil {
		t.Fatal(err)
	}
	rewound := darwinStoredPair(t, parent)
	if _, _, err := decodeMachineSnapshot(rewound, now); !errors.Is(err, ErrUnavailable) {
		t.Fatal("primary restore bypassed accepted state", err)
	}
	retry := darwinFixtureTransaction(t, parent, false)
	if result, err := commitInstallation(retry, next, nil, changeUpdate, func() time.Time { return now }); err == nil || result.Committed {
		t.Fatal("ordinary update repaired mismatched history", result, err)
	}
	if !equalDarwinPair(rewound, darwinStoredPair(t, parent)) {
		t.Fatal("rejected rollback was overwritten")
	}
}

func TestDarwinNativePairRejectsUnrelatedAndStaleCounter(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	for _, extra := range []bool{true, false} {
		name := "counter-change"
		if extra {
			name = "unrelated"
		}
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			stored := darwinFixtureInstall(t, parent, prior, now)
			before := darwinStoredPair(t, parent)
			tx := darwinFixtureTransaction(t, parent, false)
			if _, _, err := tx.Read(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := tx.ReadAcceptance(); err != nil {
				t.Fatal(err)
			}
			candidate, _, err := installationTransition(stored, next, nil, false, now)
			if err != nil {
				t.Fatal(err)
			}
			source, record, err := prepareNativeAcceptance(candidate, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.StageAccepted(source, record); err != nil {
				t.Fatal(err)
			}
			unchanged := darwinStoredPair(t, parent)
			if !equalDarwinPair(before, unchanged) {
				t.Fatal("staged pair became visible")
			}
			path := filepath.Join(parent, darwinPolicyDirectory, darwinAcceptanceFile)
			value := append(bytes.Clone(before.acceptance), ' ')
			if extra {
				path = filepath.Join(parent, darwinPolicyDirectory, "unrelated")
				value = []byte("preserve this independently owned object")
			}
			if err := os.WriteFile(path, value, 0644); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err == nil {
				t.Fatal("unsupported/stale directory published")
			}
			if err := tx.Close(); err != nil {
				t.Fatal(err)
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(retained, value) {
				t.Fatal("rejected publication changed unrelated/counter contents", err)
			}
			sourceAfter, err := os.ReadFile(filepath.Join(parent, darwinPolicyDirectory, darwinPolicyFile))
			if err != nil || !bytes.Equal(sourceAfter, before.source) {
				t.Fatal("rejected pair replaced source", err)
			}
		})
	}
}

func TestDarwinNativePairRecoveryUsesIntactAcceptedFloor(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	darwinFixtureInstall(t, parent, prior, now)
	update := darwinFixtureTransaction(t, parent, false)
	if result, err := commitInstallation(update, next, nil, changeUpdate, func() time.Time { return now }); err != nil || !result.Committed {
		t.Fatal(err)
	}
	path := filepath.Join(parent, darwinPolicyDirectory, darwinPolicyFile)
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	before := darwinStoredPair(t, parent)
	stale, public, _, _ := recoveryFixture(t, nil, time.Hour)
	denied := darwinFixtureTransaction(t, parent, false)
	if result, err := commitRecovery(denied, stale, public, 2, func() time.Time { return now }); !errors.Is(err, ErrDenied) || result.Committed {
		t.Fatal("stale floor erased accepted revision", result, err)
	}
	if !equalDarwinPair(before, darwinStoredPair(t, parent)) {
		t.Fatal("rejected repair mutated pair")
	}
	nextPublic, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(Policy{SchemaVersion: 1, Revision: 4, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(payload, nextPrivate, now)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := SignRecovery(nil, envelope, nextPrivate, 2, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	allowed := darwinFixtureTransaction(t, parent, false)
	result, err := commitRecovery(allowed, approval, nextPublic, 2, func() time.Time { return now })
	if err != nil || !result.Committed || result.PreviousRevision != 3 || result.Revision != 4 {
		t.Fatal("fresh paired repair failed", result, err)
	}
	authority, accepted, err := decodeMachineSnapshot(darwinStoredPair(t, parent), now)
	if err != nil || accepted.revision != 4 || authority.verified.KeyID != KeyID(nextPublic) {
		t.Fatal("repaired pair failed native read", err)
	}
}

func TestDarwinNativePairRecordAliasIsNotAuthority(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	darwinFixtureInstall(t, parent, prior, now)
	path := filepath.Join(parent, darwinPolicyDirectory, darwinAcceptanceFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(target, original, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	tx := darwinFixtureTransaction(t, parent, false)
	if result, err := commitInstallation(tx, next, nil, changeUpdate, func() time.Time { return now }); err == nil || result.Committed {
		t.Fatal("record alias supplied authority", result, err)
	}
	untouched, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(original, untouched) {
		t.Fatal("record alias changed unrelated target", err)
	}
}

func TestDarwinPairReadersNeverCombinePublishedGenerations(t *testing.T) {
	prior, _, _, private, now := renewalFixture(t)
	parent := t.TempDir()
	darwinFixtureInstall(t, parent, prior, now)
	parentFD, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentFD.Close()
	stop := make(chan struct{})
	var readers sync.WaitGroup
	failures := make(chan error, 4)
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snapshot, err := readDarwinSnapshotAt(parentFD, uint32(os.Geteuid()))
				if err != nil {
					if err.Error() == "machine policy changed repeatedly during reading" {
						continue
					}
					failures <- err
					return
				}
				if _, history, err := decodeMachineSnapshot(snapshot, now); err != nil || history == nil {
					failures <- errors.New("reader observed missing or mixed policy pair")
					return
				}
			}
		}()
	}
	defer func() {
		close(stop)
		readers.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
	}()
	for revision := uint64(3); revision < 15; revision++ {
		payload, err := json.Marshal(Policy{SchemaVersion: 1, Revision: revision, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := Sign(payload, private, now)
		if err != nil {
			t.Fatal(err)
		}
		tx := darwinFixtureTransaction(t, parent, false)
		if result, err := commitInstallation(tx, envelope, nil, changeUpdate, func() time.Time { return now }); err != nil || !result.Committed {
			t.Fatal(result, err)
		}
	}
}

func TestDarwinPublishedPairRetainsChangedDisplacedDirectory(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	stored := darwinFixtureInstall(t, parent, prior, now)
	tx := darwinFixtureTransaction(t, parent, false)
	if _, _, err := tx.Read(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tx.ReadAcceptance(); err != nil {
		t.Fatal(err)
	}
	candidate, _, err := installationTransition(stored, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	source, record, err := prepareNativeAcceptance(candidate, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.StageAccepted(source, record); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if !tx.Published() {
		t.Fatal("successful exchange concealed publication")
	}
	orphan := filepath.Join(parent, tx.pair.name)
	path := filepath.Join(orphan, darwinPolicyFile)
	changed := []byte("independent administrative change after exchange")
	if err := os.WriteFile(path, changed, 0644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Close(); err == nil {
		t.Fatal("changed displaced source was silently removed")
	}
	retained, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, changed) {
		t.Fatal("changed displaced bytes were deleted", err)
	}
	if _, history, err := decodeMachineSnapshot(darwinStoredPair(t, parent), now); err != nil || history.revision != 3 {
		t.Fatal("cleanup failure rolled back published pair", err)
	}
	nextTx := darwinFixtureTransaction(t, parent, false)
	if err := nextTx.Close(); err != nil {
		t.Fatal(err)
	}
	retained, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, changed) {
		t.Fatal("subsequent cleanup deleted damaged displaced source", err)
	}
}

func TestDarwinPairAbortAndInitialPublicationCollision(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	for _, collision := range []bool{false, true} {
		name := "abort"
		if collision {
			name = "collision"
		}
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			tx := darwinFixtureTransaction(t, parent, true)
			if _, present, err := tx.Read(); err != nil || present {
				t.Fatal("initial preimage", err)
			}
			if _, present, err := tx.ReadAcceptance(); err != nil || present {
				t.Fatal("initial history", err)
			}
			if err := tx.Stage(prior); err == nil {
				t.Fatal("one-file publication accepted")
			}
			source, record, err := prepareNativeAcceptance(prior, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.StageAccepted(source, record); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(parent, darwinPolicyDirectory)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("private stage became active", err)
			}
			stage := filepath.Join(parent, tx.pair.name)
			if collision {
				target := filepath.Join(parent, darwinPolicyDirectory)
				if err := os.Mkdir(target, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "independent"), []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(); err == nil || tx.Published() {
					t.Fatal("bootstrap overwrote a concurrent administrator directory", err)
				}
			}
			if err := tx.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("known aborted stage retained", err)
			}
			if collision {
				if data, err := os.ReadFile(filepath.Join(parent, darwinPolicyDirectory, "independent")); err != nil || string(data) != "retain" {
					t.Fatal("independent contents changed", err)
				}
			}
		})
	}
}

func TestDarwinPairHasNoLegacyHistoryFallback(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	for _, kind := range []string{"missing", "empty", "invalid", "symlink", "hardlink", "writable"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			stored := darwinFixtureInstall(t, parent, prior, now)
			path := filepath.Join(parent, darwinPolicyDirectory, darwinAcceptanceFile)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "invalid":
				if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				target := filepath.Join(parent, "external-history")
				if err := os.WriteFile(target, original, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(target, path)
				} else {
					err = os.Link(target, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			tx := darwinFixtureTransaction(t, parent, false)
			if result, err := commitInstallation(tx, next, nil, changeUpdate, func() time.Time { return now }); err == nil || result.Committed {
				t.Fatal("untrusted or absent acceptance history updated", kind, result, err)
			}
			actual, err := os.ReadFile(filepath.Join(parent, darwinPolicyDirectory, darwinPolicyFile))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, stored) {
				t.Fatal("failed update changed primary", err)
			}
		})
	}
	// A valid legacy preparation is not an enrolled macOS installation.
	parent := t.TempDir()
	dir := filepath.Join(parent, darwinPolicyDirectory)
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, darwinPolicyFile), prior, 0644); err != nil {
		t.Fatal(err)
	}
	tx := darwinFixtureTransaction(t, parent, false)
	if result, err := commitInstallation(tx, next, nil, changeUpdate, func() time.Time { return now }); err == nil || result.Committed {
		t.Fatal("legacy source bypassed mandatory accepted history", result, err)
	}
}

func TestDarwinPairRetainsModifiedCandidateBeforePublication(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	tx := darwinFixtureTransaction(t, parent, true)
	if _, _, err := tx.Read(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tx.ReadAcceptance(); err != nil {
		t.Fatal(err)
	}
	source, record, err := prepareNativeAcceptance(prior, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.StageAccepted(source, record); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, tx.pair.name, darwinPolicyFile)
	changed := append(bytes.Clone(source), ' ')
	if err := os.WriteFile(path, changed, 0644); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil || tx.Published() {
		t.Fatal("changed candidate published", err)
	}
	if err := tx.Close(); err == nil {
		t.Fatal("changed candidate silently removed")
	}
	if actual, err := os.ReadFile(path); err != nil || !bytes.Equal(actual, changed) {
		t.Fatal("changed candidate not retained", err)
	}
}

func TestDarwinPairLockSerializesWritersWithoutBlockingReaders(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	darwinFixtureInstall(t, parent, prior, now)
	first := darwinFixtureTransaction(t, parent, false)
	type outcome struct {
		tx  *darwinInstallationTransaction
		err error
	}
	waiting := make(chan outcome, 1)
	go func() {
		dir, err := os.Open(parent)
		if err != nil {
			waiting <- outcome{err: err}
			return
		}
		tx, err := beginDarwinInstallation(dir, false, uint32(os.Geteuid()))
		waiting <- outcome{tx, err}
	}()
	select {
	case result := <-waiting:
		if result.tx != nil {
			result.tx.Close()
		}
		t.Fatal("second writer entered while first holds lock", result.err)
	case <-time.After(50 * time.Millisecond):
	}
	parentFD, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, readErr := readDarwinSnapshotAt(parentFD, uint32(os.Geteuid()))
	if err := errors.Join(readErr, parentFD.Close()); err != nil {
		t.Fatal("writer lock blocked read-only inspection", err)
	}
	if _, accepted, err := decodeMachineSnapshot(snapshot, now); err != nil || accepted == nil {
		t.Fatal("reader lost accepted pair", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-waiting:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if err := result.tx.Close(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting writer did not acquire released lock")
	}
}
