//go:build linux && (amd64 || arm64)

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

func linuxStoredPair(t *testing.T, parent string) machineSnapshot {
	t.Helper()
	dir, err := os.Open(filepath.Join(parent, linuxPolicyDirectory))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, readErr := readLinuxPolicySnapshot(dir, uint32(os.Geteuid()), false)
	if err := errors.Join(readErr, dir.Close()); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestLinuxNativePairInstallMigrationAndRollback(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	for _, legacy := range []bool{false, true} {
		name := "new"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			if legacy {
				dir := filepath.Join(parent, linuxPolicyDirectory)
				if err := os.Mkdir(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, linuxPolicyFile), prior, 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				linuxFixtureInstall(t, parent, prior, now)
			}
			original := linuxStoredPair(t, parent)
			tx := linuxFixtureTransaction(t, parent, false)
			result, err := commitInstallation(tx, next, nil, changeUpdate, func() time.Time { return now })
			if err != nil || !result.Committed {
				t.Fatal("paired update/migration failed", result, err)
			}
			updated := linuxStoredPair(t, parent)
			authority, history, err := decodeMachineSnapshot(updated, now)
			if err != nil || authority.verified.Policy.Revision != 3 || history == nil || history.revision != 3 {
				t.Fatal("published pair invalid", err)
			}
			document, err := parseInstallation(updated.source)
			if err != nil || document.SchemaVersion != 2 {
				t.Fatal("native storage marker missing", err)
			}
			if err := os.WriteFile(filepath.Join(parent, linuxPolicyDirectory, linuxPolicyFile), original.source, 0644); err != nil {
				t.Fatal(err)
			}
			rewound := linuxStoredPair(t, parent)
			if _, _, err := decodeMachineSnapshot(rewound, now); !errors.Is(err, ErrUnavailable) {
				t.Fatal("restored primary bypassed accepted state", err)
			}
			retry := linuxFixtureTransaction(t, parent, false)
			if result, err := commitInstallation(retry, next, nil, changeUpdate, func() time.Time { return now }); err == nil || result.Committed {
				t.Fatal("ordinary update repaired mismatched trust state", result, err)
			}
			retained := linuxStoredPair(t, parent)
			if !policyPairEqual(retained, rewound) {
				t.Fatal("rejected rollback state was overwritten")
			}
		})
	}
}

func TestLinuxNativePairRejectsUnrelatedAndStaleCounter(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	for _, extra := range []bool{true, false} {
		name := "counter-change"
		if extra {
			name = "unrelated"
		}
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			stored := linuxFixtureInstall(t, parent, prior, now)
			before := linuxStoredPair(t, parent)
			tx := linuxFixtureTransaction(t, parent, false)
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
			unchanged := linuxStoredPair(t, parent)
			if !policyPairEqual(before, unchanged) {
				t.Fatal("staged pair became visible")
			}
			path := filepath.Join(parent, linuxPolicyDirectory, linuxAcceptanceFile)
			value := append(bytes.Clone(before.acceptance), ' ')
			if extra {
				path = filepath.Join(parent, linuxPolicyDirectory, "unrelated")
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
			sourceAfter, err := os.ReadFile(filepath.Join(parent, linuxPolicyDirectory, linuxPolicyFile))
			if err != nil || !bytes.Equal(sourceAfter, before.source) {
				t.Fatal("rejected pair replaced source", err)
			}
		})
	}
}

func TestLinuxNativePairRecoveryUsesIntactAcceptedFloor(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	linuxFixtureInstall(t, parent, prior, now)
	update := linuxFixtureTransaction(t, parent, false)
	if result, err := commitInstallation(update, next, nil, changeUpdate, func() time.Time { return now }); err != nil || !result.Committed {
		t.Fatal(err)
	}
	path := filepath.Join(parent, linuxPolicyDirectory, linuxPolicyFile)
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	before := linuxStoredPair(t, parent)
	stale, public, _, _ := recoveryFixture(t, nil, time.Hour)
	denied := linuxFixtureTransaction(t, parent, false)
	if result, err := commitRecovery(denied, stale, public, 2, func() time.Time { return now }); !errors.Is(err, ErrDenied) || result.Committed {
		t.Fatal("stale floor erased accepted revision", result, err)
	}
	if !policyPairEqual(before, linuxStoredPair(t, parent)) {
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
	allowed := linuxFixtureTransaction(t, parent, false)
	result, err := commitRecovery(allowed, approval, nextPublic, 2, func() time.Time { return now })
	if err != nil || !result.Committed || result.PreviousRevision != 3 || result.Revision != 4 {
		t.Fatal("fresh paired repair failed", result, err)
	}
	authority, accepted, err := decodeMachineSnapshot(linuxStoredPair(t, parent), now)
	if err != nil || accepted.revision != 4 || authority.verified.KeyID != KeyID(nextPublic) {
		t.Fatal("repaired pair failed native read", err)
	}
}

func TestLinuxNativePairRecordAliasIsNotAuthority(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	linuxFixtureInstall(t, parent, prior, now)
	path := filepath.Join(parent, linuxPolicyDirectory, linuxAcceptanceFile)
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
	tx := linuxFixtureTransaction(t, parent, false)
	if result, err := commitInstallation(tx, next, nil, changeUpdate, func() time.Time { return now }); err == nil || result.Committed {
		t.Fatal("record alias supplied authority", result, err)
	}
	untouched, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(original, untouched) {
		t.Fatal("record alias changed unrelated target", err)
	}
}

func TestLinuxPairReadersNeverCombinePublishedGenerations(t *testing.T) {
	prior, _, _, private, now := renewalFixture(t)
	parent := t.TempDir()
	linuxFixtureInstall(t, parent, prior, now)
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
				snapshot, err := readLinuxSnapshotAt(parentFD, uint32(os.Geteuid()), false)
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
		tx := linuxFixtureTransaction(t, parent, false)
		if result, err := commitInstallation(tx, envelope, nil, changeUpdate, func() time.Time { return now }); err != nil || !result.Committed {
			t.Fatal(result, err)
		}
	}
}

func TestLinuxPublishedPairRetainsChangedDisplacedDirectory(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	parent := t.TempDir()
	stored := linuxFixtureInstall(t, parent, prior, now)
	tx := linuxFixtureTransaction(t, parent, false)
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
	path := filepath.Join(orphan, linuxPolicyFile)
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
	if _, history, err := decodeMachineSnapshot(linuxStoredPair(t, parent), now); err != nil || history.revision != 3 {
		t.Fatal("cleanup failure rolled back published pair", err)
	}
	nextTx := linuxFixtureTransaction(t, parent, false)
	if err := nextTx.Close(); err != nil {
		t.Fatal(err)
	}
	retained, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, changed) {
		t.Fatal("subsequent cleanup deleted damaged displaced source", err)
	}
}
