//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ownedRemovalDirectoryCaseCount = 22

func retainedRemovalDirectorySnapshot(t *testing.T, f *ownedRemovalTargetFixture) []byte {
	t.Helper()
	values := map[string]string{}
	if e := json.Unmarshal(retainedRemovalFixtureSnapshot(t, f), &values); e != nil {
		t.Fatal(e)
	}
	// Removing the recorded roots changes only these retained parents' ordinary
	// directory timestamps/link counts. The engine still checks their frozen
	// device/inode and protected modes/owners, and enumerates every child.
	delete(values, filepath.Join(deploymentRoot, "versions"))
	delete(values, "owned-incoming")
	raw, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func completeOwnedRemovalFiles(t *testing.T, f *ownedRemovalTargetFixture) {
	t.Helper()
	for i := 1; i <= 2; i++ {
		got, e := f.intent.removeNextProtectedFileUsing(context.Background(), f.resolve)
		if e != nil || got != (removalFileProgress{i, 2}) {
			t.Fatal("file prefix failed", got, e)
		}
	}
}
func completeOwnedRemovalObjects(t *testing.T, f *ownedRemovalTargetFixture) {
	t.Helper()
	for i := 0; i < 6; i++ {
		got, e := f.intent.removeNextProtectedObjectUsing(context.Background(), f.resolve, false)
		if e != nil || got.total != 6 || got.completed < 3 || got.completed > 6 {
			t.Fatal("directory retry failed", got, e)
		}
		if got.completed == 6 {
			return
		}
	}
	t.Fatal("directory progress did not complete")
}
func exerciseOwnedRemovalDirectoryTransactions(t *testing.T, privateBase string) {
	t.Helper()
	cases := []string{"complete", "intent-fault", "unlink-fault", "parent-sync-fault", "done-fault", "root-unlink-fault", "partial-intent", "partial-done", "missing-unrecorded-directory", "directory-mode", "replaced-directory", "directory-alias", "replaced-root", "root-alias", "extra-receipt-after-root-removal", "nonempty-directory", "recreated-completed-directory", "missing-other-pending", "extra-core-after-root-removal", "extra-incoming-after-root-removal", "cancelled", "file-phase-retry"}
	if len(cases) != ownedRemovalDirectoryCaseCount {
		t.Fatal("directory case count differs")
	}
	for _, kind := range cases {
		if !t.Run("protected-directory-journal-"+kind, func(t *testing.T) {
			f := newOwnedRemovalTargetFixture(t, privateBase, true)
			retained := retainedRemovalDirectorySnapshot(t, f)
			completeOwnedRemovalFiles(t, f)
			coreDirectory := filepath.Dir(f.coreFile)
			coreRoot := filepath.Dir(coreDirectory)
			inputDirectory := filepath.Dir(f.incomingFile)
			actions, e := removalProtectedActions(f.intent.plan)
			if e != nil || len(actions) != 6 {
				t.Fatal(actions, e)
			}
			ctx := context.Background()
			refusal := false
			step := func() {
				t.Helper()
				if _, e := f.intent.removeNextProtectedObjectUsing(ctx, f.resolve, false); e != nil {
					t.Fatal(e)
				}
			}
			fault := func(phase string) {
				t.Helper()
				f.store.observe = func(actual string) error {
					if phase == actual {
						return errors.New("owned injected directory boundary")
					}
					return nil
				}
				got, e := f.intent.removeNextProtectedObjectUsing(ctx, f.resolve, false)
				f.store.observe = nil
				if e == nil || got != (removalProgress{}) {
					t.Fatal("directory boundary not refused", got, e)
				}
			}
			partial := func() {
				t.Helper()
				raw, _, j, e := readRemovalJournalAt(f.store.current, 0, removalJournalSeed(f.intent.fence), 6)
				if e != nil {
					t.Fatal(e)
				}
				line, e := nextRemovalJournalLine(removalJournalSeed(f.intent.fence), j)
				if e != nil {
					t.Fatal(e)
				}
				name := filepath.Join(f.base, deploymentRoot, "state", removalJournalName)
				if e := os.WriteFile(name, append(raw, line[:len(line)/2]...), 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "complete":
			case "intent-fault":
				fault("removal-directory-intent-durable")
			case "unlink-fault":
				fault("removal-directory-unlinked")
			case "parent-sync-fault":
				fault("removal-directory-parent-durable")
			case "done-fault":
				fault("removal-directory-done-durable")
			case "root-unlink-fault":
				step()
				fault("removal-directory-unlinked")
			case "partial-intent":
				partial()
			case "partial-done":
				fault("removal-directory-unlinked")
				partial()
			case "missing-unrecorded-directory":
				if e := os.Remove(coreDirectory); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "directory-mode":
				if e := os.Chmod(coreDirectory, 0775); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "replaced-directory":
				if e := os.Rename(coreDirectory, filepath.Join(f.base, "retained-original-directory")); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(coreDirectory, 0755); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "directory-alias":
				if e := os.Remove(coreDirectory); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(f.publicRoot, coreDirectory); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "replaced-root":
				retainedRoot := filepath.Join(f.base, "retained-original-core-root")
				if e := os.Rename(coreRoot, retainedRoot); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(coreRoot, 0755); e != nil {
					t.Fatal(e)
				}
				if e := os.Rename(filepath.Join(retainedRoot, filepath.Base(coreDirectory)), coreDirectory); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "root-alias":
				if e := os.Remove(coreDirectory); e != nil {
					t.Fatal(e)
				}
				if e := os.Remove(coreRoot); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(f.publicRoot, coreRoot); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "extra-receipt-after-root-removal":
				step()
				step()
				if e := os.WriteFile(filepath.Join(f.receiptRoot, BundleID+".unknown.bom"), []byte("unrecorded receipt"), 0644); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "nonempty-directory":
				if e := os.WriteFile(filepath.Join(coreDirectory, "unrecorded"), []byte("retain"), 0644); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "recreated-completed-directory":
				step()
				if e := os.Mkdir(coreDirectory, 0755); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "missing-other-pending":
				fault("removal-directory-intent-durable")
				if e := os.Remove(inputDirectory); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "extra-core-after-root-removal":
				step()
				step()
				if e := os.Mkdir(filepath.Join(f.base, deploymentRoot, "versions", strings.Repeat("f", 32)), 0755); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "extra-incoming-after-root-removal":
				completeOwnedRemovalObjects(t, f)
				key := strings.Repeat("f", 64)
				if key == f.intent.plan.Active.Identity.ManifestSHA256 {
					key = strings.Repeat("a", 64)
				}
				if e := os.Mkdir(filepath.Join(f.incomingParent, key), 0755); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
				refusal = true
			case "file-phase-retry":
				step()
				before := ownedRemovalTargetSnapshot(t, f.base)
				got, e := f.intent.removeNextProtectedFileUsing(ctx, f.resolve)
				if e != nil || got != (removalFileProgress{2, 2}) || !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("file prefix retry changed directory progress", got, e)
				}
			}
			if refusal {
				before := ownedRemovalTargetSnapshot(t, f.base)
				got, e := f.intent.removeNextProtectedObjectUsing(ctx, f.resolve, false)
				if e == nil || got != (removalProgress{}) {
					t.Fatal("unsafe directory progress accepted", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("directory refusal changed fixture")
				}
				return
			}
			reopenOwnedRemovalFileIntent(t, f)
			completeOwnedRemovalObjects(t, f)
			reopenOwnedRemovalFileIntent(t, f)
			before := ownedRemovalTargetSnapshot(t, f.base)
			got, e := f.intent.removeNextProtectedObjectUsing(ctx, f.resolve, false)
			if e != nil || got != (removalProgress{6, 6}) || !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
				t.Fatal("directory completion not idempotent", got, e)
			}
			files, e := f.intent.removeNextProtectedFileUsing(ctx, f.resolve)
			if e != nil || files != (removalFileProgress{2, 2}) || !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
				t.Fatal("completed file prefix not idempotent", files, e)
			}
			for _, name := range []string{coreRoot, f.incomingRoot} {
				if _, e := os.Lstat(name); !os.IsNotExist(e) {
					t.Fatal("journaled root remains", name, e)
				}
			}
			if !bytes.Equal(retained, retainedRemovalDirectorySnapshot(t, f)) {
				t.Fatal("directory removal changed retained data")
			}
		}) {
			t.Fatalf("owned directory case failed: %s", kind)
		}
	}
}
