//go:build darwin && (amd64 || arm64)

package managed

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDarwinNativeMutationErrorsPreserveKnownPublication(t *testing.T) {
	faults := []struct {
		name, phase string
		published   bool
	}{
		{"candidate-descriptor-closed", "candidate-mode", false},
		{"parent-closed-before-publication", "candidate.fullsync", false},
		{"parent-closed-after-publication", "publication-returned", true},
		{"committed-lock-close-error", "parent.fullsync", true},
		{"changed-displaced-contents", "parent.fullsync", true},
	}
	for _, operation := range []string{"install", "update", "rotate", "recover"} {
		for _, fault := range faults {
			if operation == "install" && fault.name == "changed-displaced-contents" {
				continue
			}
			t.Run("operation="+operation+"/fault="+fault.name, func(t *testing.T) {
				prior, input, public, _, now := renewalFixture(t)
				expectedKey := KeyID(public)
				if operation == "install" {
					input = prior
				}
				if operation == "rotate" {
					f := rotationFixture(t)
					prior, input, public, now = f.prior, f.rotation, f.oldPublic, f.now
					expectedKey = KeyID(f.newPublic)
				}
				parent := t.TempDir()
				before := machineSnapshot{}
				if operation != "install" {
					darwinFixtureInstall(t, parent, prior, now)
					if operation == "recover" {
						damaged := []byte("damaged primary remains blocked until signed repair")
						if err := os.WriteFile(filepath.Join(parent, darwinPolicyDirectory, darwinPolicyFile), damaged, 0644); err != nil {
							t.Fatal(err)
						}
						input, public, _, now = recoveryFixture(t, damaged, time.Hour)
						expectedKey = KeyID(public)
					}
					before = darwinStoredPair(t, parent)
				}
				apply := func(observer func(*darwinInstallationTransaction, string)) (InstallResult, error) {
					dir, err := os.Open(parent)
					if err != nil {
						return InstallResult{}, err
					}
					var tx *darwinInstallationTransaction
					if observer == nil {
						tx, err = beginDarwinInstallation(dir, operation == "install", uint32(os.Geteuid()))
					} else {
						tx, err = beginDarwinInstallationObserved(dir, operation == "install", uint32(os.Geteuid()), observer)
					}
					if err != nil {
						return InstallResult{}, err
					}
					if operation == "recover" {
						return commitRecovery(tx, input, public, 2, func() time.Time { return now })
					}
					change := changeUpdate
					if operation == "install" {
						change = changeInstall
					} else if operation == "rotate" {
						change = changeRotate
					}
					return commitInstallation(tx, input, public, change, func() time.Time { return now })
				}
				fired := false
				var lockInfo os.FileInfo
				var displaced string
				changed := []byte("independent administrator change must survive cleanup failure")
				result, err := apply(func(tx *darwinInstallationTransaction, phase string) {
					if phase != fault.phase {
						return
					}
					if fired {
						t.Fatal("fault boundary repeated")
					}
					fired = true
					info, statErr := tx.lock.Stat()
					if statErr != nil {
						t.Fatal(statErr)
					}
					lockInfo = info
					switch fault.name {
					case "candidate-descriptor-closed":
						if err := tx.pair.dir.Close(); err != nil {
							t.Fatal(err)
						}
					case "parent-closed-before-publication", "parent-closed-after-publication":
						if err := tx.parent.Close(); err != nil {
							t.Fatal(err)
						}
					case "committed-lock-close-error":
						if err := tx.lock.Close(); err != nil {
							t.Fatal(err)
						}
					case "changed-displaced-contents":
						if tx.pair == nil || tx.pair.name == "" || !tx.Published() {
							t.Fatal("displaced generation not published")
						}
						displaced = filepath.Join(parent, tx.pair.name, darwinPolicyFile)
						if err := os.WriteFile(displaced, changed, 0644); err != nil {
							t.Fatal(err)
						}
					}
				})
				if !fired || err == nil || result.Committed != fault.published {
					t.Fatal("native error concealed publication outcome", fired, result, err)
				}
				if fault.name != "changed-displaced-contents" && !errors.Is(err, os.ErrClosed) && !errors.Is(err, unix.EBADF) {
					t.Fatal("native descriptor failure lost its cause", err)
				}
				if result.Operation != operation {
					t.Fatal("operation identity lost", result)
				}
				read := func() machineSnapshot {
					dir, err := os.Open(parent)
					if err != nil {
						t.Fatal(err)
					}
					snapshot, readErr := readDarwinSnapshotAt(dir, uint32(os.Geteuid()))
					if err := errors.Join(readErr, dir.Close()); err != nil {
						t.Fatal(err)
					}
					return snapshot
				}
				actual := read()
				if !fault.published {
					if actual.present != before.present || !equalDarwinPair(actual, before) {
						t.Fatal("failed pre-publication operation changed active state")
					}
					if operation == "recover" {
						if _, _, err := decodeMachineSnapshot(actual, now); err == nil {
							t.Fatal("failed repair enabled damaged policy")
						}
					}
				} else {
					authority, history, err := decodeMachineSnapshot(actual, now)
					revision := uint64(3)
					if operation == "install" {
						revision = 2
					}
					if err != nil || authority == nil || history == nil || history.revision != revision || authority.verified.KeyID != expectedKey || result.Revision != revision || result.KeyID != expectedKey {
						t.Fatal("published policy lost signature, key, accepted history or result identity", result, err)
					}
				}
				stages, err := filepath.Glob(filepath.Join(parent, darwinStagePrefix+"*"))
				if err != nil {
					t.Fatal(err)
				}
				wantStages := 1
				if fault.name == "committed-lock-close-error" || (operation == "install" && fault.published) {
					wantStages = 0
				}
				if len(stages) != wantStages {
					t.Fatal("unexpected retained native generation", len(stages), wantStages)
				}
				stageInfo := map[string]os.FileInfo{}
				stageBytes := map[string]map[string][]byte{}
				for _, stage := range stages {
					info, err := os.Lstat(stage)
					if err != nil {
						t.Fatal(err)
					}
					stageInfo[stage] = info
					stageBytes[stage] = readDarwinAbandonedFixture(t, stage)
				}
				if displaced != "" {
					value, err := os.ReadFile(displaced)
					if err != nil || !bytes.Equal(value, changed) {
						t.Fatal("cleanup removed independent displaced bytes", err)
					}
				}
				// A fresh native writer must acquire the same lock after every error. A
				// published request is rejected on replay; an unpublished request may retry.
				probe := darwinFixtureTransaction(t, parent, operation == "install" && !fault.published)
				probeLock, probeErr := probe.lock.Stat()
				if probeErr != nil || !os.SameFile(lockInfo, probeLock) {
					t.Fatal("error lost the coordination identity", probeErr)
				}
				if err := probe.Close(); err != nil {
					t.Fatal("fresh writer did not release its lease", err)
				}
				retried, retryErr := apply(nil)
				if fault.published {
					if retryErr == nil || retried.Committed {
						t.Fatal("failed command was automatically safe to replay despite publication", retried, retryErr)
					}
					if !equalDarwinPair(read(), actual) {
						t.Fatal("replay changed the committed generation")
					}
				} else {
					if retryErr != nil || !retried.Committed {
						t.Fatal("native error leaked writer ownership or blocked a valid explicit retry", retried, retryErr)
					}
					authority, history, err := decodeMachineSnapshot(read(), now)
					if err != nil || authority == nil || history == nil || authority.verified.KeyID != expectedKey || history.revision != retried.Revision {
						t.Fatal("explicit retry failed authentication or accepted history", err)
					}
				}
				currentLock, err := os.Stat(filepath.Join(parent, darwinPolicyLock))
				if err != nil || !os.SameFile(lockInfo, currentLock) {
					t.Fatal("native error replaced the writer-lock namespace", err)
				}
				afterStages, err := filepath.Glob(filepath.Join(parent, darwinStagePrefix+"*"))
				if err != nil || len(afterStages) != len(stages) {
					t.Fatal("later operation changed retained abandoned namespace", err)
				}
				for _, stage := range stages {
					info, err := os.Lstat(stage)
					if err != nil || !os.SameFile(info, stageInfo[stage]) {
						t.Fatal("later operation replaced retained directory", err)
					}
					values := readDarwinAbandonedFixture(t, stage)
					if len(values) != len(stageBytes[stage]) {
						t.Fatal("later operation changed retained layout")
					}
					for name, want := range stageBytes[stage] {
						if !bytes.Equal(values[name], want) {
							t.Fatal("later operation changed retained bytes", name)
						}
					}
				}
			})
		}
	}
}
