//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

var removalPreparationKillPhases = []string{
	"removal-preparation-created", "removal-state-durable", "removal-plan-durable",
	"removal-marker-durable", "removal-directory-durable", "removal-preparation-durable",
	"removal-record-reserved", "removal-reservation-parent-durable",
	"removal-published", "removal-parent-durable",
}

const ownedPreparationPlan = "owned-preparation-plan.json"
const ownedPreparationFence = "owned-preparation-fence.json"

// The fixed capsule and phase are checked by the existing guarded child before
// this path runs. Only canonical test-owned metadata selects a synthetic plan;
// no product path, installed executable or caller-selected receipt is opened.
func runOwnedRemovalPreparationKilledChild(t *testing.T, parent *os.File, base, phase string) {
	t.Helper()
	s, e := openRemovalAuthorityAt(parent, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.encoded, e = s.readRecord(s.current)
	if e != nil {
		t.Fatal(e)
	}
	s.state, e = decodeDeployment(s.encoded)
	if e != nil {
		t.Fatal(e)
	}
	after, e := s.state.deactivate()
	if e != nil {
		t.Fatal(e)
	}
	afterRaw, e := encodeDeployment(after)
	if e != nil {
		t.Fatal(e)
	}
	planRaw, planStat, e := readAt(s.parent, ownedPreparationPlan, maxRemovalPlanBytes)
	if e != nil || planStat.Mode&07777 != 0600 {
		t.Fatal("owned preparation plan protection", e)
	}
	plan, e := decodeRemovalPlan(planRaw)
	if e != nil {
		t.Fatal(e)
	}
	marker, markerStat, e := readAt(s.parent, ownedPreparationFence, maxDeploymentRecord)
	if e != nil || markerStat.Mode&07777 != 0600 {
		t.Fatal("owned preparation marker protection", e)
	}
	fence, _, e := decodeRemovalFence(marker, afterRaw)
	if e != nil {
		t.Fatal(e)
	}
	identity := deploymentFixtureSlot(1, "0.1.1-alpha").Identity
	if fence.Target.Identity != identity || fence.DesktopRecordSHA256 != removalDigest([]byte("owned synthetic registration")) {
		t.Fatal("owned preparation seals differ")
	}
	r := &removalIntentStore{store: s, fence: fence, plan: plan}
	f := &ownedRemovalTargetFixture{base: base, store: s, intent: r}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for pass := 0; pass < 2; pass++ {
		if e := s.checkRemovalPreimage(fence, plan, ""); e != nil {
			t.Fatal(e)
		}
		for _, root := range plan.Roots {
			if e := r.verifyIntactTarget(ctx, root, f.resolve); e != nil {
				t.Fatal(e)
			}
		}
	}
	s.observe = ownedRemovalKillObserver(phase)
	published, e := s.publishRemovalFence(fence, plan)
	t.Fatal("preparation returned before actual kill", published, e)
}

func retainedOwnedPreparationTargets(t *testing.T, f *ownedRemovalTargetFixture) []byte {
	t.Helper()
	values := map[string]string{}
	if e := json.Unmarshal(ownedRemovalTargetSnapshot(t, f.base), &values); e != nil {
		t.Fatal(e)
	}
	for name := range values {
		if name == "." || name == deploymentRoot || strings.HasPrefix(name, deploymentRoot+string(os.PathSeparator)) || name == removalPreparationRoot || strings.HasPrefix(name, removalPreparationRoot+string(os.PathSeparator)) {
			delete(values, name)
		}
	}
	raw, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// A separate guarded invocation keeps each native test process under its
// existing 120-second deadline. The larger transaction fixture is unchanged.
func TestDarwinRemovalPreparationRootKilledRecovery(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST") != "1" {
		t.Skip("requires opted-in hosted native package driver")
	}
	if !ownedRemovalKillHost() {
		t.Fatal("preparation SIGKILL requires disposable hosted root")
	}
	parent, e := os.MkdirTemp("/private/tmp", "accessweaver-deployment-")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if filepath.Dir(parent) != "/private/tmp" || !strings.HasPrefix(filepath.Base(parent), "accessweaver-deployment-") {
			t.Error("unsafe preparation fixture cleanup")
			return
		}
		if e := os.RemoveAll(parent); e != nil {
			t.Error(e)
		}
	}()
	if e := os.Chown(parent, 0, 0); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	bridge := filepath.Join(parent, "schema2-bridge")
	if e := os.Mkdir(bridge, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Chown(bridge, 0, 0); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(bridge, 0755); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	records := []map[string]any{}
	for index, phase := range removalPreparationKillPhases {
		if !t.Run("preparation-sigkill-"+phase, func(t *testing.T) {
			f := newOwnedRemovalTargetFixture(t, bridge, true, true, true)
			fence, plan := f.intent.fence, f.intent.plan
			active := append([]byte{}, f.store.encoded...)
			after, e := f.store.state.deactivate()
			if e != nil {
				t.Fatal(e)
			}
			afterRaw, e := encodeDeployment(after)
			if e != nil {
				t.Fatal(e)
			}
			planRaw, e := encodeRemovalPlan(plan)
			if e != nil {
				t.Fatal(e)
			}
			marker, e := encodeRemovalFence(fence, after)
			if e != nil {
				t.Fatal(e)
			}
			for _, item := range []struct {
				name string
				data []byte
			}{{ownedPreparationPlan, planRaw}, {ownedPreparationFence, marker}} {
				file, e := darwintrust.CreateRegularAt(f.store.parent, item.name, 0)
				if e != nil {
					t.Fatal(e)
				}
				if e := file.Chown(0, 0); e != nil {
					file.Close()
					t.Fatal(e)
				}
				n, writeErr := file.Write(item.data)
				if n != len(item.data) {
					writeErr = errors.Join(writeErr, errors.New("short owned preparation input"))
				}
				if e := errors.Join(writeErr, fullDeploymentSync(file), file.Close()); e != nil {
					t.Fatal(e)
				}
			}
			if e := fullDeploymentSync(f.store.parent); e != nil {
				t.Fatal(e)
			}
			retained := retainedOwnedPreparationTargets(t, f)
			if e := f.intent.Close(); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			command := exec.CommandContext(ctx, executable, "-test.run=^TestDarwinRemovalFileKilledChild$", "-test.v", "-test.timeout=15s")
			command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "TZ=UTC", "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "RUNNER_OS=macOS", "ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST=1", removalKillBaseEnv + "=" + f.base, removalKillPhaseEnv + "=" + phase}
			output := &ownedRemovalKillOutput{}
			command.Stdout = output
			command.Stderr = output
			started := time.Now()
			e = command.Run()
			elapsed := time.Since(started).Milliseconds()
			contextError := ctx.Err()
			cancel()
			var exit *exec.ExitError
			if contextError != nil || !errors.As(e, &exit) {
				t.Fatal("preparation child termination differs", e, contextError, string(output.data))
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || bytes.Count(output.data, []byte("OWNED-REMOVAL-SIGKILL "+phase+"\n")) != 1 {
				t.Fatal("preparation child signal/marker differs", e, string(output.data))
			}
			external := filepath.Join(f.base, removalPreparationRoot, fence.DisplacedRecord)
			reserved := filepath.Join(f.base, deploymentRoot, fence.DisplacedRecord)
			stateAtTermination := "external-preparation"
			stageFiles := index
			if stageFiles > 3 {
				stageFiles = 3
			}
			outside := index < 6
			published := index >= 8
			if !outside {
				stateAtTermination = "reserved-preparation"
			}
			if published {
				stateAtTermination = "published-intent"
			}
			var oldStage []byte
			if outside {
				if _, e := os.Lstat(reserved); !os.IsNotExist(e) {
					t.Fatal("partial bundle entered authority", e)
				}
				stage, e := os.Open(external)
				if e != nil {
					t.Fatal(e)
				}
				mode := os.FileMode(0700)
				if index >= 4 {
					mode = 0755
				}
				if e := deploymentObject(stage, true, 0, mode); e != nil {
					stage.Close()
					t.Fatal(e)
				}
				names, e := deploymentEntries(stage, 0, 3)
				if e != nil || len(names) != stageFiles {
					stage.Close()
					t.Fatal("preparation file extent differs", len(names), e)
				}
				expected := []struct {
					name string
					data []byte
				}{{deploymentRecord, afterRaw}, {removalPlanName, planRaw}, {removalFenceName, marker}}
				for _, item := range expected[:stageFiles] {
					raw, st, e := readAt(stage, item.name, maxRemovalPlanBytes)
					if e != nil || st.Mode&07777 != 0644 || !bytes.Equal(raw, item.data) {
						stage.Close()
						t.Fatal("preparation file bytes/protection differ", item.name, e)
					}
				}
				if e := stage.Close(); e != nil {
					t.Fatal(e)
				}
				oldStage = ownedRemovalTargetSnapshot(t, external)
			} else if !published {
				stage, e := os.Open(reserved)
				if e != nil {
					t.Fatal(e)
				}
				names, e := deploymentEntries(stage, 0, 3)
				if e != nil || len(names) != 3 {
					stage.Close()
					t.Fatal("reserved preparation extent differs", len(names), e)
				}
				seen, captured, _, readErr := readRemovalBundle(stage, 0)
				if e := errors.Join(readErr, stage.Close()); e != nil || seen != fence || sameRemovalPlans(plan, captured) != nil {
					t.Fatal("reserved preparation incomplete", e)
				}
				if _, e := os.Lstat(external); !os.IsNotExist(e) {
					t.Fatal("reserved preparation still external", e)
				}
			}
			reopenedParent, e := os.Open(f.base)
			if e != nil {
				t.Fatal(e)
			}
			if outside {
				s, e := beginDeploymentMode(reopenedParent, 0, nil, false)
				if e != nil {
					t.Fatal("external preparation blocked ordinary reopen", e)
				}
				if !bytes.Equal(s.encoded, active) {
					s.Close()
					t.Fatal("active preimage changed")
				}
				fresh, _, e := newRemovalFence(s.state, fence.DesktopRecordSHA256, fence.InventorySHA256, plan)
				if e != nil {
					s.Close()
					t.Fatal(e)
				}
				f.store = s
				f.intent = &removalIntentStore{store: s, fence: fresh, plan: plan}
				if published, e := s.publishRemovalFence(fresh, plan); !published || e != nil {
					t.Fatal("fresh retry failed", published, e)
				}
				if !bytes.Equal(oldStage, ownedRemovalTargetSnapshot(t, external)) {
					t.Fatal("fresh retry changed old external preparation")
				}
			} else if !published {
				recovered, done, e := resumePreparedRemovalUsing(context.Background(), reopenedParent, 0, fence.Target.Identity, fence.DesktopRecordSHA256, ownedPreparationResolver(f))
				if recovered != nil {
					f.intent = recovered
					f.store = recovered.store
				}
				if e != nil || !done || recovered == nil {
					t.Fatal("complete reserved preparation did not resume", done, e)
				}
			} else {
				f.intent, e = openRemovalIntentAt(reopenedParent, 0, fence.Target.Identity, fence.DesktopRecordSHA256)
				if e != nil {
					t.Fatal("published preparation did not reopen", e)
				}
				f.store = f.intent.store
				names, e := deploymentEntries(f.store.current, 0, 3)
				if e != nil || len(names) != 3 {
					t.Fatal("published preparation extent differs", len(names), e)
				}
				if _, e := f.store.readRecord(f.store.current); e == nil {
					t.Fatal("ordinary reader accepted the published removal bundle")
				}
				if _, e := os.Lstat(external); !os.IsNotExist(e) {
					t.Fatal("published preparation still external", e)
				}
			}
			if e := f.intent.syncRemovalBarrier(); e != nil {
				t.Fatal(e)
			}
			for pass := 0; pass < 2; pass++ {
				if _, e := f.intent.verifyIntactTargetsUsing(context.Background(), f.resolve); e != nil {
					t.Fatal("preparation changed intact payload", e)
				}
				reopenOwnedRemovalFileIntent(t, f)
			}
			if !bytes.Equal(retained, retainedOwnedPreparationTargets(t, f)) {
				t.Fatal("preparation changed retained data")
			}
			records = append(records, map[string]any{"phase": phase, "signal": int(status.Signal()), "elapsedMilliseconds": elapsed, "timedOut": contextError != nil, "stateAtTermination": stateAtTermination, "stageFileCountAtTermination": stageFiles, "intentPublishedAtTermination": published, "freshRetryPublished": outside, "reservedRecoveryPublished": !outside && !published, "publishedIntentReopened": published, "bothLeasesReacquired": true, "completedIntentReopenVerified": true, "activePreimageRetained": true, "preparationEvidencePreserved": true, "payloadObjectsRemoved": 0, "retainedDataPreserved": true, "passed": true})
		}) {
			t.Fatalf("owned preparation SIGKILL failed: %s", phase)
		}
	}
	if len(records) != 10 {
		t.Fatal("preparation SIGKILL case extent differs")
	}
	encoded, e := json.Marshal(map[string]any{"schemaVersion": 1, "caseCount": len(records), "cases": records, "copiedCodeExecuted": false, "packageScriptsIntegrated": false, "productionQualificationComplete": false})
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println("REMOVAL-PREPARATION-RESULT " + string(encoded))
}
