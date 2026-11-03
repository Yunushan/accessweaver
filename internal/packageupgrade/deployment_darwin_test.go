//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

func deploymentFixtureStore(t *testing.T, parent string, observe func(string) error) *deploymentStore {
	t.Helper()
	f, e := os.Open(parent)
	if e != nil {
		t.Fatal(e)
	}
	s, e := beginDeployment(f, uint32(os.Geteuid()), observe)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	})
	return s
}
func TestDarwinDeploymentRecordRecoveryAtPublicationBoundaries(t *testing.T) {
	for _, phase := range []string{"slot-reserved", "record-reserved", "record-file-durable", "record-directory-durable", "record-published", "record-parent-durable"} {
		t.Run(phase, func(t *testing.T) {
			parent := t.TempDir()
			s := deploymentFixtureStore(t, parent, nil)
			before := append([]byte{}, s.encoded...)
			s.observe = func(p string) error {
				if p == phase {
					return errors.New("injected stop")
				}
				return nil
			}
			if _, e := s.prepare(deploymentFixtureSlot(1, "0.1.0").Identity); e == nil {
				t.Fatal("injected stop did not fire")
			}
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			reopened := deploymentFixtureStore(t, parent, nil)
			published := phase == "record-published" || phase == "record-parent-durable"
			if published {
				if len(reopened.state.Pending) != 1 {
					t.Fatal("published preparation lost")
				}
			} else if !bytes.Equal(before, reopened.encoded) {
				t.Fatal("pre-publication failure changed active record")
			}
			entries, e := os.ReadDir(filepath.Join(parent, deploymentRoot, "versions"))
			if e != nil || len(entries) != 1 {
				t.Fatal("reserved evidence was deleted", e)
			}
		})
	}
}
func TestDarwinDeploymentLockAndChangedAuthorityRefused(t *testing.T) {
	parent := t.TempDir()
	s := deploymentFixtureStore(t, parent, nil)
	f, e := os.Open(parent)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := beginDeployment(f, uint32(os.Geteuid()), nil); e == nil {
		other.Close()
		t.Fatal("second writer acquired authority")
	}
	before := append([]byte{}, s.encoded...)
	old := filepath.Join(parent, "preserved")
	if e = os.Rename(filepath.Join(parent, deploymentRoot), old); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(parent, deploymentRoot), 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = s.prepare(deploymentFixtureSlot(1, "0.1.0").Identity); e == nil {
		t.Fatal("replaced authority accepted")
	}
	data, e := os.ReadFile(filepath.Join(old, "state", deploymentRecord))
	if e != nil || !bytes.Equal(data, before) {
		t.Fatal("refusal changed held state", e)
	}
}
func TestDarwinDeploymentChangedRecordAndSlotPreserved(t *testing.T) {
	parent := t.TempDir()
	s := deploymentFixtureStore(t, parent, nil)
	slot, e := s.prepare(deploymentFixtureSlot(1, "0.1.0").Identity)
	if e != nil {
		t.Fatal(e)
	}
	slotPath := filepath.Join(parent, deploymentRoot, "versions", slot.ID)
	if e = os.Rename(slotPath, slotPath+"-preserved"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(slotPath, 0700); e != nil {
		t.Fatal(e)
	}
	if f, e := s.openSlot(slot); e == nil {
		f.Close()
		t.Fatal("changed reserved inode accepted")
	}
	path := filepath.Join(parent, deploymentRoot, "state", deploymentRecord)
	changed := append(append([]byte{}, s.encoded...), '\n')
	if e = os.WriteFile(path, changed, 0644); e != nil {
		t.Fatal(e)
	}
	next, e := s.state.abandon(slot.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.commit(next); e == nil {
		t.Fatal("changed state preimage accepted")
	}
	actual, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(actual, changed) {
		t.Fatal("changed record was overwritten", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(parent)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := beginDeployment(f, uint32(os.Geteuid()), nil); e == nil {
		other.Close()
		t.Fatal("noncanonical record recovered by guessing")
	}
}
func TestDarwinDeploymentUnknownAuthorityPreservedWithoutBootstrapWrite(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, deploymentRoot)
	if e := os.Mkdir(root, 0755); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(root, "unrecognized")
	if e := os.WriteFile(marker, []byte("preserve"), 0644); e != nil {
		t.Fatal(e)
	}
	before, e := os.Stat(marker)
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(parent)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := beginDeployment(f, uint32(os.Geteuid()), nil); e == nil {
		other.Close()
		t.Fatal("unknown authority accepted")
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 1 || entries[0].Name() != "unrecognized" {
		t.Fatal("refusal created coordination/state", e)
	}
	after, e := os.Stat(marker)
	if e != nil || !os.SameFile(before, after) {
		t.Fatal("unknown object identity changed", e)
	}
	actual, e := os.ReadFile(marker)
	if e != nil || string(actual) != "preserve" {
		t.Fatal("unknown bytes changed", e)
	}
}
func TestDarwinDeploymentMissingVersionsHistoryIsPreserved(t *testing.T) {
	for _, kind := range []string{"current-state", "displaced-history"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			s := deploymentFixtureStore(t, parent, nil)
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			root := filepath.Join(parent, deploymentRoot)
			if e := os.Rename(filepath.Join(root, "versions"), filepath.Join(parent, "preserved-versions")); e != nil {
				t.Fatal(e)
			}
			if kind == "displaced-history" {
				if e := os.Rename(filepath.Join(root, "state"), filepath.Join(root, ".record-"+strings.Repeat("a", 32))); e != nil {
					t.Fatal(e)
				}
			}
			before, e := os.ReadDir(root)
			if e != nil {
				t.Fatal(e)
			}
			f, e := os.Open(parent)
			if e != nil {
				t.Fatal(e)
			}
			if other, e := beginDeployment(f, uint32(os.Geteuid()), nil); e == nil {
				other.Close()
				t.Fatal("missing versions history initialized")
			}
			after, e := os.ReadDir(root)
			if e != nil || len(after) != len(before) {
				t.Fatal("refusal changed retained authority inventory", e)
			}
			for i := range before {
				if before[i].Name() != after[i].Name() {
					t.Fatal("retained authority names changed")
				}
			}
			if _, e = os.Lstat(filepath.Join(root, "versions")); !os.IsNotExist(e) {
				t.Fatal("missing versions were recreated", e)
			}
		})
	}
}
func TestDarwinDeploymentNonPrepareCannotInitialize(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			parent := t.TempDir()
			if partial {
				if e := os.Mkdir(filepath.Join(parent, deploymentRoot), 0755); e != nil {
					t.Fatal(e)
				}
			}
			f, e := os.Open(parent)
			if e != nil {
				t.Fatal(e)
			}
			if other, e := beginDeploymentMode(f, uint32(os.Geteuid()), nil, false); e == nil {
				other.Close()
				t.Fatal("non-prepare initialized state")
			}
			root := filepath.Join(parent, deploymentRoot)
			if partial {
				entries, e := os.ReadDir(root)
				if e != nil || len(entries) != 0 {
					t.Fatal("non-prepare changed partial authority", e)
				}
			} else if _, e = os.Lstat(root); !os.IsNotExist(e) {
				t.Fatal("non-prepare created authority", e)
			}
		})
	}
}
func TestDarwinDeploymentAliasesAndPartialInitialHistoryRefused(t *testing.T) {
	for _, kind := range []string{"root-alias", "lock-alias", "state-alias", "orphan-record"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			target := t.TempDir()
			marker := filepath.Join(target, "preserve")
			if e := os.WriteFile(marker, []byte("unrelated"), 0600); e != nil {
				t.Fatal(e)
			}
			if kind == "root-alias" {
				if e := os.Symlink(target, filepath.Join(parent, deploymentRoot)); e != nil {
					t.Fatal(e)
				}
			} else {
				s := deploymentFixtureStore(t, parent, nil)
				if e := s.Close(); e != nil {
					t.Fatal(e)
				}
				root := filepath.Join(parent, deploymentRoot)
				if kind == "orphan-record" {
					if e := os.Rename(filepath.Join(root, "state"), filepath.Join(root, ".record-"+strings.Repeat("a", 32))); e != nil {
						t.Fatal(e)
					}
				} else {
					leaf := deploymentLock
					if kind == "state-alias" {
						leaf = "state"
					}
					if e := os.Rename(filepath.Join(root, leaf), filepath.Join(root, ".record-"+strings.Repeat("a", 32))); e != nil {
						t.Fatal(e)
					}
					if e := os.Symlink(target, filepath.Join(root, leaf)); e != nil {
						t.Fatal(e)
					}
				}
			}
			f, e := os.Open(parent)
			if e != nil {
				t.Fatal(e)
			}
			if other, e := beginDeployment(f, uint32(os.Geteuid()), nil); e == nil {
				other.Close()
				t.Fatal("ambiguous/aliased state accepted")
			}
			actual, e := os.ReadFile(marker)
			if e != nil || string(actual) != "unrelated" {
				t.Fatal("refusal changed unrelated destination", e)
			}
		})
	}
}

// Only the opted-in hosted package driver invokes this root-only test, after
// installing the exact package. Ordinary CI runs skip it; no app code is run
// elevated. All mutation is confined to a new private test-owned APFS parent.
func TestDarwinDeploymentRootCopyRecovery(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST") != "1" {
		t.Skip("requires opted-in hosted native package driver")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("root deployment probe requires a disposable hosted Mac")
	}
	protected, e := darwintrust.OpenRootDirectory(deploymentParent)
	if e != nil {
		t.Fatal("fixed production parent protection", e)
	}
	protected.Close()
	apps, e := applications()
	if e != nil {
		t.Fatal(e)
	}
	defer apps.Close()
	source, e := directoryAt(apps, "AccessWeaver.app")
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	encoded, e := readPath(source, ManifestName, 2<<20)
	if e != nil {
		t.Fatal(e)
	}
	core, e := readPath(source, "Contents/MacOS/accessweaver", 64<<20)
	if e != nil {
		t.Fatal(e)
	}
	buildData, e := readPath(source, "Contents/Resources/BUILD-INFO.json", 16384)
	if e != nil {
		t.Fatal(e)
	}
	var build struct {
		Version string `json:"version"`
	}
	if e = json.Unmarshal(buildData, &build); e != nil {
		t.Fatal(e)
	}
	identity := deploymentIdentity{build.Version, digest(encoded), digest(core)}
	parent, e := os.MkdirTemp("/private/tmp", "accessweaver-deployment-")
	if e != nil {
		t.Fatal(e)
	}
	// t.TempDir-style cleanup is confined to this exclusively created fixture,
	// after its absolute parent/name and all in-test paths have been checked.
	defer func() {
		if filepath.Dir(parent) != "/private/tmp" || !strings.HasPrefix(filepath.Base(parent), "accessweaver-deployment-") {
			t.Error("unsafe fixture cleanup")
			return
		}
		if e := os.RemoveAll(parent); e != nil {
			t.Error(e)
		}
	}()
	s := deploymentFixtureStore(t, parent, nil)
	partial, e := s.prepare(identity)
	if e != nil {
		t.Fatal(e)
	}
	s.observe = func(p string) error {
		if p == "payload-file-durable" {
			return errors.New("injected partial copy")
		}
		return nil
	}
	if published, e := s.copyAndActivate(partial, source); published || e == nil {
		t.Fatal("partial copy published")
	}
	s.observe = nil
	if published, e := s.activatePrepared(partial); published || e == nil {
		t.Fatal("partial copy recovered as complete")
	}
	if s.state.Active != (deploymentSlot{}) {
		t.Fatal("partial copy changed active state")
	}
	if _, e = s.abandon(partial.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(parent, deploymentRoot, "versions", partial.ID)); e != nil {
		t.Fatal("abandoned copy evidence deleted")
	}
	complete, e := s.prepare(identity)
	if e != nil {
		t.Fatal(e)
	}
	s.observe = func(p string) error {
		if p == "payload-complete" {
			return errors.New("injected complete copy interruption")
		}
		return nil
	}
	if published, e := s.copyAndActivate(complete, source); published || e == nil {
		t.Fatal("complete-copy interruption was not retained before publication")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = deploymentFixtureStore(t, parent, nil)
	if published, e := s.activatePrepared(complete); !published || e != nil {
		t.Fatal("complete-copy recovery", e)
	}
	stale, e := s.prepare(identity)
	if e != nil {
		t.Fatal(e)
	}
	replacement, e := s.prepare(identity)
	if e != nil {
		t.Fatal(e)
	}
	if published, e := s.copyAndActivate(replacement, source); !published || e != nil {
		t.Fatal("replacement", e)
	}
	if published, e := s.copyAndActivate(stale, source); published || e == nil {
		t.Fatal("concurrent old preparation activated")
	}
	s.observe = func(p string) error {
		if p == "record-published" {
			return errors.New("injected post-publication interruption")
		}
		return nil
	}
	if published, e := s.deactivate(); !published || e == nil {
		t.Fatal("post-publication outcome not explicit")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = deploymentFixtureStore(t, parent, nil)
	if s.state.Active != (deploymentSlot{}) || s.state.Generation != 3 {
		t.Fatal("removal tombstone not recovered")
	}
	if published, e := s.activatePrepared(replacement); published || e == nil {
		t.Fatal("removal reactivated old complete slot")
	}
	retry, e := s.prepare(identity)
	if e != nil {
		t.Fatal(e)
	}
	if published, e := s.copyAndActivate(retry, source); !published || e != nil {
		t.Fatal("restored retry", e)
	}
	// Distinct inode proves the active payload is a copy rather than a hard link
	// into package-receipt-owned staging. The fixture does not execute it.
	saved, e := os.Stat(filepath.Join(parent, deploymentRoot, "versions", retry.ID, "AccessWeaver.app", "Contents/MacOS/accessweaver"))
	if e != nil {
		t.Fatal(e)
	}
	original, e := os.Stat("/Applications/AccessWeaver.app/Contents/MacOS/accessweaver")
	if e != nil {
		t.Fatal(e)
	}
	if os.SameFile(saved, original) {
		t.Fatal("active payload aliases package staging")
	}
	if e = s.verifySlot(retry); e != nil {
		t.Fatal(e)
	}
	if s.state.Generation != 4 {
		t.Fatal("unexpected generation")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	// Exercise interruption at the new external-manifest durability boundary
	// using only another exclusively owned temporary authority/source tree.
	containerPath := filepath.Join(parent, "detached-source")
	if e = os.Mkdir(containerPath, 0755); e != nil {
		t.Fatal(e)
	}
	appPath := filepath.Join(containerPath, "AccessWeaver.app")
	if e = os.CopyFS(appPath, os.DirFS("/Applications/AccessWeaver.app")); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(appPath, ManifestName), filepath.Join(containerPath, detachedDeploymentManifest)); e != nil {
		t.Fatal(e)
	}
	container, e := os.Open(containerPath)
	if e != nil {
		t.Fatal(e)
	}
	defer container.Close()
	detachedParent := filepath.Join(parent, "detached-authority")
	if e = os.Mkdir(detachedParent, 0755); e != nil {
		t.Fatal(e)
	}
	detached := deploymentFixtureStore(t, detachedParent, nil)
	manifestOnly, e := detached.prepare(identity)
	if e != nil {
		t.Fatal(e)
	}
	detached.observe = func(phase string) error {
		if phase == "payload-manifest-durable" {
			return errors.New("injected detached manifest interruption")
		}
		return nil
	}
	if published, e := detached.copyIncomingAndActivate(manifestOnly, container); published || e == nil {
		t.Fatal("manifest-only copy published", e)
	}
	detached.observe = nil
	if published, e := detached.activatePrepared(manifestOnly); published || e == nil {
		t.Fatal("manifest-only copy recovered as complete", e)
	}
	if detached.state.Active != (deploymentSlot{}) {
		t.Fatal("manifest-only copy changed active state")
	}
	if _, e = detached.abandon(manifestOnly.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(detachedParent, deploymentRoot, "versions", manifestOnly.ID, detachedDeploymentManifest)); e != nil {
		t.Fatal("partial manifest evidence lost", e)
	}
	whole, e := detached.prepare(identity)
	if e != nil {
		t.Fatal(e)
	}
	detached.observe = func(phase string) error {
		if phase == "payload-complete" {
			return errors.New("injected detached complete-copy interruption")
		}
		return nil
	}
	if published, e := detached.copyIncomingAndActivate(whole, container); published || e == nil {
		t.Fatal("complete detached copy interruption was not retained", e)
	}
	if e = detached.Close(); e != nil {
		t.Fatal(e)
	}
	detached = deploymentFixtureStore(t, detachedParent, nil)
	if published, e := detached.activatePrepared(whole); !published || e != nil {
		t.Fatal("complete detached copy recovery", e)
	}
	if detached.state.Generation != 1 {
		t.Fatal("unexpected detached recovery generation")
	}
	if e = detached.Close(); e != nil {
		t.Fatal(e)
	}
	report := map[string]any{"schemaVersion": 1, "manifestSHA256": identity.ManifestSHA256, "payloadSHA256": identity.PayloadSHA256, "version": identity.Version, "fixedProtectedParentVerified": true, "partialCopyPreservedAndRefused": true, "completeCopyRecovered": true, "concurrentPreparationFenced": true, "postPublicationRemovalRecovered": true, "oldCompleteSlotFencedAfterRemoval": true, "restoredRetryVerified": true, "payloadIsIndependentCopy": true, "detachedManifestPartialCopyPreservedAndRefused": true, "detachedManifestCompleteCopyRecovered": true, "copiedCodeExecuted": false, "productionQualificationComplete": false, "finalGeneration": 4}
	data, _ := json.Marshal(report)
	t.Log("DEPLOYMENT-RESULT " + string(data))
}
