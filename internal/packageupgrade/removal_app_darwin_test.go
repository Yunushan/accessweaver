//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ownedRemovalAppCaseCount = 32

func TestDarwinRemovalRegistrationRecovery(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST") != "1" {
		t.Skip("requires opted-in hosted macOS runner")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("registration removal test requires a disposable hosted Mac")
	}
	for _, phase := range []string{"intent-durable", "unlinked", "parent-durable", "done-durable", "changed", "missing"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			f := newOwnedRemovalTargetFixture(t, t.TempDir(), true, true)
			// Match the production registration parent mode inside the private test root.
			if e := os.Chmod(f.base, 0755); e != nil {
				t.Fatal(e)
			}
			if e := f.intent.quarantinePublicAppUsing(ctx, f.resolve); e != nil {
				t.Fatal(e)
			}
			if progress, e := f.intent.removeNextRegistrationUsing(ctx, f.resolve); e == nil || progress != (removalProgress{}) {
				t.Fatal("registration retirement preceded payload removal", progress, e)
			}
			completeOwnedRemovalObjects(t, f)
			completeOwnedQuarantinedApp(t, f)
			name := "desktop-" + f.intent.plan.DesktopRecordSHA256 + ".json"
			path := filepath.Join(f.registrationRoot, name)
			refusal := phase == "changed" || phase == "missing"
			switch phase {
			case "changed":
				if e := os.WriteFile(path, []byte("independent registration change"), 0644); e != nil {
					t.Fatal(e)
				}
			case "missing":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
			}
			before := ownedRemovalTargetSnapshot(t, f.base)
			hit := false
			f.store.observe = func(actual string) error {
				if actual == "removal-registration-"+phase {
					hit = true
					return errors.New("injected registration interruption")
				}
				return nil
			}
			progress, e := f.intent.removeNextRegistrationUsing(ctx, f.resolve)
			if e == nil || progress != (removalProgress{}) || hit == refusal {
				t.Fatal("registration operation did not stop at the intended boundary", progress, hit, e)
			}
			if refusal {
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("registration refusal changed the fixture")
				}
				return
			}

			retained := func() map[string]string {
				t.Helper()
				values := map[string]string{}
				if e := json.Unmarshal(retainedRemovalQuarantineSnapshot(t, f), &values); e != nil {
					t.Fatal(e)
				}
				delete(values, desktopRoot)
				delete(values, filepath.Join(desktopRoot, name))
				return values
			}
			remaining := retained()
			reopenOwnedRemovalFileIntent(t, f)
			for retry := 0; retry < 2; retry++ {
				progress, e := f.intent.removeNextRegistrationUsing(ctx, f.resolve)
				if e != nil || progress != (removalProgress{10, 10}) {
					t.Fatal("registration retry did not finish", progress, e)
				}
				reopenOwnedRemovalFileIntent(t, f)
			}
			if entries, e := os.ReadDir(f.registrationRoot); e != nil || len(entries) != 0 {
				t.Fatal("registration directory did not remain empty and present", e)
			}
			if !maps.Equal(remaining, retained()) {
				t.Fatal("registration retirement changed retained receipts, history or user data")
			}
		})
	}
}

func completeOwnedQuarantinedApp(t *testing.T, f *ownedRemovalTargetFixture) {
	t.Helper()
	for attempt := 0; attempt < 4; attempt++ {
		got, e := f.intent.removeNextQuarantinedAppObjectUsing(context.Background(), f.resolve)
		if e != nil || got.total != 9 || got.completed < 7 || got.completed > 9 {
			t.Fatal("app removal did not advance", got, e)
		}
		if got.completed == 9 {
			return
		}
	}
	t.Fatal("app removal did not finish")
}
func exerciseOwnedQuarantinedAppRemoval(t *testing.T, privateBase string) {
	t.Helper()
	cases := []string{"complete", "file-intent-fault", "file-unlink-fault", "file-parent-fault", "file-done-fault", "directory-intent-fault", "directory-unlink-fault", "directory-parent-fault", "directory-done-fault", "root-intent-fault", "root-unlink-fault", "root-parent-fault", "root-done-fault", "partial-intent", "partial-done", "changed-file", "file-alias", "file-hardlink", "extra-file", "recreated-file", "recreated-root", "public-name-reappeared", "extra-receipt", "cancelled", "requires-complete-protected", "requires-quarantine", "completed-file-sync-refusal", "completed-state-sync-refusal", "prefix-ack-after-app-progress", "prefix-preserves-partial-app-record", "missing-unrecorded-root", "root-alias"}
	if len(cases) != ownedRemovalAppCaseCount {
		t.Fatal("app removal case count differs")
	}
	for _, kind := range cases {
		if !t.Run("quarantined-app-removal-"+kind, func(t *testing.T) {
			// Each case owns a separate targets-* tree, intent and lease and
			// spawns no child. Share the existing -test.parallel budget; the
			// enclosing group joins every case before emitting its report.
			t.Parallel()
			f := newOwnedRemovalTargetFixture(t, privateBase, true, true)
			retained := retainedRemovalQuarantineSnapshot(t, f)
			ctx := context.Background()
			if kind != "requires-quarantine" {
				if e := f.intent.quarantinePublicAppUsing(ctx, f.resolve); e != nil {
					t.Fatal(e)
				}
			}
			if kind != "requires-complete-protected" {
				for i := 1; i <= 6; i++ {
					var got removalProgress
					var e error
					if kind == "requires-quarantine" {
						got, e = f.intent.removeNextProtectedObjectUsing(ctx, f.resolve, false)
					} else {
						got, e = f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, false)
					}
					if e != nil || got != (removalProgress{i, 6}) {
						t.Fatal("app fixture protected prefix failed", got, e)
					}
				}
			}
			state := filepath.Join(f.base, deploymentRoot, "state")
			root := filepath.Join(state, removalQuarantineName)
			file := filepath.Join(root, "owned-public-dir", "owned-public")
			directory := filepath.Dir(file)
			journalPath := filepath.Join(state, removalJournalName)
			step := func() {
				t.Helper()
				if _, e := f.intent.removeNextQuarantinedAppObjectUsing(ctx, f.resolve); e != nil {
					t.Fatal(e)
				}
			}
			fault := func(phase string) {
				t.Helper()
				f.store.observe = func(actual string) error {
					if actual == phase {
						return errors.New("owned injected app removal boundary")
					}
					return nil
				}
				got, e := f.intent.removeNextQuarantinedAppObjectUsing(ctx, f.resolve)
				f.store.observe = nil
				if e == nil || got != (removalProgress{}) {
					t.Fatal("app boundary not refused", got, e)
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
			partial := func() {
				t.Helper()
				raw, _, j, e := readRemovalJournalAt(f.store.current, 0, removalJournalSeed(f.intent.fence), 9)
				if e != nil {
					t.Fatal(e)
				}
				line, e := nextRemovalJournalLine(removalJournalSeed(f.intent.fence), j)
				if e != nil {
					t.Fatal(e)
				}
				write(journalPath, append(raw, line[:len(line)/2]...), 0600)
			}
			refusal := false
			switch kind {
			case "complete":
			case "file-intent-fault", "file-unlink-fault", "file-parent-fault", "file-done-fault":
				phases := map[string]string{"file-intent-fault": "intent-durable", "file-unlink-fault": "unlinked", "file-parent-fault": "parent-durable", "file-done-fault": "done-durable"}
				fault("removal-app-file-" + phases[kind])
			case "directory-intent-fault", "directory-unlink-fault", "directory-parent-fault", "directory-done-fault", "root-intent-fault", "root-unlink-fault", "root-parent-fault", "root-done-fault":
				step()
				if strings.HasPrefix(kind, "root-") {
					step()
				}
				suffix := "intent-durable"
				if strings.Contains(kind, "unlink") {
					suffix = "unlinked"
				} else if strings.Contains(kind, "parent") {
					suffix = "parent-durable"
				} else if strings.Contains(kind, "done") {
					suffix = "done-durable"
				}
				fault("removal-app-directory-" + suffix)
			case "partial-intent":
				partial()
			case "partial-done":
				fault("removal-app-file-unlinked")
				partial()
			case "changed-file":
				write(file, []byte("keep changed app bytes"), 0644)
				refusal = true
			case "file-alias":
				if e := os.Remove(file); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(filepath.Join(f.base, "private-profile"), file); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "file-hardlink":
				if e := os.Remove(file); e != nil {
					t.Fatal(e)
				}
				if e := os.Link(filepath.Join(f.base, "private-profile"), file); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "extra-file":
				write(filepath.Join(directory, "unknown-private"), []byte("keep unknown app object"), 0600)
				refusal = true
			case "recreated-file":
				step()
				write(file, []byte("keep recreated app object"), 0644)
				refusal = true
			case "recreated-root":
				completeOwnedQuarantinedApp(t, f)
				if e := os.Mkdir(root, 0755); e != nil {
					t.Fatal(e)
				}
				if e := os.Chown(root, 0, 0); e != nil {
					t.Fatal(e)
				}
				write(filepath.Join(root, "unknown"), []byte("keep recreated root"), 0600)
				refusal = true
			case "public-name-reappeared":
				write(f.publicRoot, []byte("keep new public app name"), 0600)
				refusal = true
			case "extra-receipt":
				write(filepath.Join(f.receiptRoot, BundleID+".unknown.plist"), []byte("keep unrecorded receipt"), 0644)
				refusal = true
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				refusal = true
			case "requires-complete-protected", "requires-quarantine":
				refusal = true
			case "missing-unrecorded-root", "root-alias":
				if e := os.Rename(root, filepath.Join(f.base, "retained-original-app")); e != nil {
					t.Fatal(e)
				}
				if kind == "root-alias" {
					if e := os.Symlink(filepath.Join(f.base, "private-profile"), root); e != nil {
						t.Fatal(e)
					}
				}
				refusal = true
			case "completed-file-sync-refusal", "completed-state-sync-refusal":
				step()
				step()
				phase := "removal-journal-before-file-sync"
				if kind == "completed-state-sync-refusal" {
					phase = "removal-journal-before-directory-sync"
				}
				f.store.observe = func(actual string) error {
					if actual == phase {
						_, _, j, e := readRemovalJournalAt(f.store.current, 0, removalJournalSeed(f.intent.fence), 9)
						if e != nil {
							return e
						}
						if j.completed == 9 {
							return errors.New("owned final app completion sync unavailable")
						}
					}
					return nil
				}
				got, e := f.intent.removeNextQuarantinedAppObjectUsing(ctx, f.resolve)
				f.store.observe = nil
				if e == nil || got != (removalProgress{}) {
					t.Fatal("app completion sync failure accepted", got, e)
				}
				reopenOwnedRemovalFileIntent(t, f)
				f.store.observe = func(actual string) error {
					if actual == phase {
						return errors.New("owned completion synchronization still unavailable")
					}
					return nil
				}
				got, e = f.intent.removeNextQuarantinedAppObjectUsing(ctx, f.resolve)
				f.store.observe = nil
				if e == nil || got != (removalProgress{}) {
					t.Fatal("readable app completion acknowledged without sync", got, e)
				}
			case "prefix-ack-after-app-progress", "prefix-preserves-partial-app-record":
				if kind == "prefix-ack-after-app-progress" {
					step()
				} else {
					partial()
				}
				before := ownedRemovalTargetSnapshot(t, f.base)
				for _, filesOnly := range []bool{false, true} {
					got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, filesOnly)
					total := 6
					if filesOnly {
						total = 2
					}
					if e != nil || got != (removalProgress{total, total}) {
						t.Fatal("protected prefix acknowledgment changed", got, e)
					}
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("protected acknowledgment changed app progress/tail")
				}
			}
			if refusal {
				before := ownedRemovalTargetSnapshot(t, f.base)
				got, e := f.intent.removeNextQuarantinedAppObjectUsing(ctx, f.resolve)
				if e == nil || got != (removalProgress{}) {
					t.Fatal("app removal refusal accepted", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("app refusal changed retained objects")
				}
				return
			}
			reopenOwnedRemovalFileIntent(t, f)
			completeOwnedQuarantinedApp(t, f)
			reopenOwnedRemovalFileIntent(t, f)
			before := ownedRemovalTargetSnapshot(t, f.base)
			got, e := f.intent.removeNextQuarantinedAppObjectUsing(ctx, f.resolve)
			if e != nil || got != (removalProgress{9, 9}) {
				t.Fatal("app completion not idempotent", got, e)
			}
			if e := f.intent.quarantinePublicAppUsing(ctx, f.resolve); e != nil {
				t.Fatal("quarantine completion lost after app deletion", e)
			}
			for _, filesOnly := range []bool{false, true} {
				got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, filesOnly)
				total := 6
				if filesOnly {
					total = 2
				}
				if e != nil || got != (removalProgress{total, total}) {
					t.Fatal("protected prefix changed after app completion", got, e)
				}
			}
			if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) || !bytes.Equal(retained, retainedRemovalQuarantineSnapshot(t, f)) {
				t.Fatal("app removal changed retained data")
			}
			if _, e := os.Lstat(root); !os.IsNotExist(e) {
				t.Fatal("quarantined app root remains", e)
			}
			if _, e := os.Lstat(f.publicRoot); !os.IsNotExist(e) {
				t.Fatal("public app name reappeared", e)
			}
		}) {
			t.FailNow()
		}
	}
}
