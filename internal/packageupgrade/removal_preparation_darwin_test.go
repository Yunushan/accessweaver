//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const ownedRemovalPreparationCaseCount = 28

func ownedPreparationResolver(f *ownedRemovalTargetFixture) func(*removalIntentStore) removalParentResolver {
	return func(r *removalIntentStore) removalParentResolver {
		return (&ownedRemovalTargetFixture{base: f.base, store: r.store, intent: r}).resolve
	}
}
func exerciseOwnedRemovalPreparation(t *testing.T, privateBase string) {
	t.Helper()
	cases := []string{"created-retry", "state-retry", "plan-retry", "marker-retry", "directory-retry", "prepared-retry", "reserved-resume", "reservation-sync-resume", "changed-target", "missing-target", "public-alias", "changed-history", "changed-plan", "missing-marker", "unknown-stage-object", "stage-alias", "ambiguous", "compiled-core", "compiled-desktop", "runtime-busy", "missing-writer", "preparation-alias", "preparation-mode", "preparation-capacity", "cancelled", "barrier-state-sync", "barrier-history-sync", "barrier-root-sync"}
	if len(cases) != ownedRemovalPreparationCaseCount {
		t.Fatal("preparation case extent differs")
	}
	for _, kind := range cases {
		if !t.Run("removal-preparation-"+kind, func(t *testing.T) {
			if strings.HasPrefix(kind, "barrier-") {
				f := newOwnedRemovalTargetFixture(t, privateBase, true, true)
				phase := map[string]string{"barrier-state-sync": "removal-barrier-before-state-sync", "barrier-history-sync": "removal-barrier-before-history-sync", "barrier-root-sync": "removal-barrier-before-root-sync"}[kind]
				hit := false
				f.store.observe = func(actual string) error {
					if actual == phase {
						hit = true
						return errors.New("owned barrier synchronization unavailable")
					}
					return nil
				}
				before := ownedRemovalTargetSnapshot(t, f.base)
				if e := f.intent.quarantinePublicAppUsing(context.Background(), f.resolve); e == nil || !hit {
					t.Fatal("quarantine ignored unavailable barrier synchronization", e)
				}
				hit = false
				if got, e := f.intent.removeNextProtectedObjectUsing(context.Background(), f.resolve, false); e == nil || got != (removalProgress{}) || !hit {
					t.Fatal("protected removal ignored unavailable barrier synchronization", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("barrier refusal changed targets")
				}
				f.store.observe = nil
				if e := f.intent.quarantinePublicAppUsing(context.Background(), f.resolve); e != nil {
					t.Fatal(e)
				}
				for i := 1; i <= 6; i++ {
					got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(context.Background(), f.resolve, false)
					if e != nil || got != (removalProgress{i, 6}) {
						t.Fatal(got, e)
					}
				}
				completeOwnedQuarantinedApp(t, f)
				reopenOwnedRemovalFileIntent(t, f)
				before = ownedRemovalTargetSnapshot(t, f.base)
				hit = false
				f.store.observe = func(actual string) error {
					if actual == phase {
						hit = true
						return errors.New("owned completion barrier sync unavailable")
					}
					return nil
				}
				if got, e := f.intent.removeNextQuarantinedAppObjectUsing(context.Background(), f.resolve); e == nil || got != (removalProgress{}) || !hit {
					t.Fatal("completion ignored unavailable barrier synchronization", got, e)
				}
				f.store.observe = nil
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("completion barrier refusal changed data")
				}
				return
			}
			f := newOwnedRemovalTargetFixture(t, privateBase, true, true, true)
			fence, plan := f.intent.fence, f.intent.plan
			active := append([]byte{}, f.store.encoded...)
			prep := filepath.Join(f.base, removalPreparationRoot)
			external := filepath.Join(prep, fence.DisplacedRecord)
			reserved := filepath.Join(f.base, deploymentRoot, fence.DisplacedRecord)
			mkdir := func(name string, mode os.FileMode) {
				t.Helper()
				if e := os.Mkdir(name, mode); e != nil {
					t.Fatal(e)
				}
				if e := os.Chown(name, 0, 0); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(name, mode); e != nil {
					t.Fatal(e)
				}
			}
			write := func(name string, raw []byte, mode os.FileMode) {
				t.Helper()
				if e := os.WriteFile(name, raw, mode); e != nil {
					t.Fatal(e)
				}
				if e := os.Chown(name, 0, 0); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(name, mode); e != nil {
					t.Fatal(e)
				}
			}
			if strings.HasPrefix(kind, "preparation-") {
				switch kind {
				case "preparation-alias":
					if e := os.Symlink(filepath.Join(f.base, "private-profile"), prep); e != nil {
						t.Fatal(e)
					}
				case "preparation-mode":
					mkdir(prep, 0755)
				case "preparation-capacity":
					mkdir(prep, 0700)
					for i := 0; i < maxRemovalPreparations; i++ {
						mkdir(filepath.Join(prep, fmt.Sprintf(".record-%032x", i+1)), 0700)
					}
				}
				before := ownedRemovalTargetSnapshot(t, f.base)
				if published, e := f.store.publishRemovalFence(fence, plan); published || e == nil {
					t.Fatal("unsafe preparation accepted", published, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("preparation admission refusal changed data")
				}
				return
			}
			phase := "removal-record-reserved"
			phases := map[string]string{"created-retry": "removal-preparation-created", "state-retry": "removal-state-durable", "plan-retry": "removal-plan-durable", "marker-retry": "removal-marker-durable", "directory-retry": "removal-directory-durable", "prepared-retry": "removal-preparation-durable", "reservation-sync-resume": "removal-reservation-parent-durable"}
			if value, ok := phases[kind]; ok {
				phase = value
			}
			hit := false
			f.store.observe = func(actual string) error {
				if actual == phase {
					hit = true
					return errors.New("owned preparation interruption")
				}
				return nil
			}
			published, e := f.store.publishRemovalFence(fence, plan)
			f.store.observe = nil
			if published || e == nil || !hit {
				t.Fatal("preparation boundary not reached", published, e)
			}
			if raw, e := f.store.readRecord(f.store.current); e != nil || !bytes.Equal(raw, active) {
				t.Fatal("preparation changed active state", e)
			}
			outside := strings.HasSuffix(kind, "-retry")
			if outside {
				if _, e := os.Lstat(reserved); !os.IsNotExist(e) {
					t.Fatal("partial preparation entered authority history", e)
				}
				retained := ownedRemovalTargetSnapshot(t, external)
				if e := f.intent.Close(); e != nil {
					t.Fatal(e)
				}
				parent, e := os.Open(f.base)
				if e != nil {
					t.Fatal(e)
				}
				ordinary, e := beginDeploymentMode(parent, 0, nil, false)
				if e != nil {
					t.Fatal("external incomplete preparation blocked ordinary reopen", e)
				}
				f.store = ordinary
				if !bytes.Equal(ordinary.encoded, active) {
					t.Fatal("ordinary reopen changed preimage")
				}
				fresh, _, e := newRemovalFence(ordinary.state, fence.DesktopRecordSHA256, fence.InventorySHA256, plan)
				if e != nil {
					t.Fatal(e)
				}
				f.intent = &removalIntentStore{store: ordinary, fence: fresh, plan: plan}
				if published, e := ordinary.publishRemovalFence(fresh, plan); !published || e != nil {
					t.Fatal("fresh preparation retry failed", published, e)
				}
				if !bytes.Equal(retained, ownedRemovalTargetSnapshot(t, external)) {
					t.Fatal("fresh retry repaired/removed unknown external preparation")
				}
				reopenOwnedRemovalFileIntent(t, f)
				if _, e := f.intent.verifyIntactTargetsUsing(context.Background(), f.resolve); e != nil {
					t.Fatal(e)
				}
				return
			}
			observed, captured, _, e := func() (removalFence, removalPlan, []byte, error) {
				dir, e := os.Open(reserved)
				if e != nil {
					return removalFence{}, removalPlan{}, nil, e
				}
				defer dir.Close()
				return readRemovalBundle(dir, 0)
			}()
			if e != nil || observed != fence || sameRemovalPlans(plan, captured) != nil {
				t.Fatal("authority reservation was not a complete exact bundle", e)
			}
			if e := f.intent.Close(); e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			identity, seal := fence.Target.Identity, fence.DesktopRecordSHA256
			refusal := false
			var reader *os.File
			switch kind {
			case "reserved-resume", "reservation-sync-resume":
			case "changed-target":
				write(f.publicFile, []byte("keep changed public bytes"), 0644)
				refusal = true
			case "missing-target":
				if e := os.Rename(f.publicFile, filepath.Join(f.base, "retained-public-file")); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "public-alias":
				if e := os.Rename(f.publicRoot, filepath.Join(f.base, "retained-public-app")); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(filepath.Join(f.base, "private-profile"), f.publicRoot); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "changed-history":
				for _, record := range plan.History {
					if record.Name != "state" {
						name := filepath.Join(f.base, deploymentRoot, record.Name, deploymentRecord)
						raw, e := os.ReadFile(name)
						if e != nil {
							t.Fatal(e)
						}
						write(name, append(raw, ' '), 0644)
						break
					}
				}
				refusal = true
			case "changed-plan":
				raw, e := os.ReadFile(filepath.Join(reserved, removalPlanName))
				if e != nil {
					t.Fatal(e)
				}
				write(filepath.Join(reserved, removalPlanName), append(raw, ' '), 0644)
				refusal = true
			case "missing-marker":
				if e := os.Remove(filepath.Join(reserved, removalFenceName)); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "unknown-stage-object":
				write(filepath.Join(reserved, "private-unknown"), []byte("keep"), 0600)
				refusal = true
			case "stage-alias":
				if e := os.Rename(reserved, filepath.Join(f.base, "retained-preparation")); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(filepath.Join(f.base, "private-profile"), reserved); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "ambiguous":
				parent, e := os.Open(f.base)
				if e != nil {
					t.Fatal(e)
				}
				s, e := openRemovalAuthorityAt(parent, 0)
				if e != nil {
					t.Fatal(e)
				}
				raw, e := s.readRecord(s.current)
				if e != nil {
					t.Fatal(e)
				}
				s.state, e = decodeDeployment(raw)
				if e != nil {
					t.Fatal(e)
				}
				s.encoded = raw
				second, after, e := newRemovalFence(s.state, seal, fence.InventorySHA256, plan)
				if e != nil {
					t.Fatal(e)
				}
				name := filepath.Join(f.base, deploymentRoot, second.DisplacedRecord)
				mkdir(name, 0755)
				afterRaw, _ := encodeDeployment(after)
				planRaw, _ := encodeRemovalPlan(plan)
				marker, _ := encodeRemovalFence(second, after)
				write(filepath.Join(name, deploymentRecord), afterRaw, 0644)
				write(filepath.Join(name, removalPlanName), planRaw, 0644)
				write(filepath.Join(name, removalFenceName), marker, 0644)
				if e := s.Close(); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "compiled-core":
				identity.PayloadSHA256 = strings.Repeat("0", 64)
				refusal = true
			case "compiled-desktop":
				seal = strings.Repeat("0", 64)
				refusal = true
			case "runtime-busy":
				root, e := os.Open(filepath.Join(f.base, deploymentRoot))
				if e != nil {
					t.Fatal(e)
				}
				reader, e = runtimeFileAt(root, 0)
				closeErr := root.Close()
				if e != nil || closeErr != nil {
					t.Fatal(e, closeErr)
				}
				if e := unix.Flock(int(reader.Fd()), unix.LOCK_SH|unix.LOCK_NB); e != nil {
					t.Fatal(e)
				}
				defer reader.Close()
				refusal = true
			case "missing-writer":
				if e := os.Remove(filepath.Join(f.base, deploymentRoot, deploymentLock)); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				refusal = true
			}
			before := ownedRemovalTargetSnapshot(t, f.base)
			parent, e := os.Open(f.base)
			if e != nil {
				t.Fatal(e)
			}
			recovered, published, e := resumePreparedRemovalUsing(ctx, parent, 0, identity, seal, ownedPreparationResolver(f))
			if refusal {
				if recovered != nil || published || e == nil {
					if recovered != nil {
						recovered.Close()
					}
					t.Fatal("unsafe preparation recovery accepted", published, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("recovery refusal changed data")
				}
				if reader == nil {
					return
				}
				if e := reader.Close(); e != nil {
					t.Fatal(e)
				}
				parent, e = os.Open(f.base)
				if e != nil {
					t.Fatal(e)
				}
				recovered, published, e = resumePreparedRemovalUsing(context.Background(), parent, 0, identity, seal, ownedPreparationResolver(f))
			}
			if e != nil || !published || recovered == nil {
				t.Fatal("complete preparation did not recover", published, e)
			}
			f.intent, f.store = recovered, recovered.store
			if _, e := f.intent.verifyIntactTargetsUsing(context.Background(), f.resolve); e != nil {
				t.Fatal("recovered target differs", e)
			}
			reopenOwnedRemovalFileIntent(t, f)
			if _, e := f.intent.verifyIntactTargetsUsing(context.Background(), f.resolve); e != nil {
				t.Fatal("recovered intent cannot reopen", e)
			}
		}) {
			t.FailNow()
		}
	}
}
