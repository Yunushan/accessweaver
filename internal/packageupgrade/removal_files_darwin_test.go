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

const ownedRemovalFileCaseCount = 18

func reopenOwnedRemovalFileIntent(t *testing.T, f *ownedRemovalTargetFixture) {
	t.Helper()
	identity, seal := f.intent.fence.Target.Identity, f.intent.fence.DesktopRecordSHA256
	if e := f.intent.Close(); e != nil {
		t.Fatal(e)
	}
	parent, e := os.Open(f.base)
	if e != nil {
		t.Fatal(e)
	}
	f.intent, e = openRemovalIntentAt(parent, 0, identity, seal)
	if e != nil {
		t.Fatal(e)
	}
	f.store = f.intent.store
}
func retainedRemovalFixtureSnapshot(t *testing.T, f *ownedRemovalTargetFixture) []byte {
	t.Helper()
	values := map[string]string{}
	if e := json.Unmarshal(ownedRemovalTargetSnapshot(t, f.base), &values); e != nil {
		t.Fatal(e)
	}
	// Only the two protected file trees and the progress-containing inactive
	// state directory are expected to change. Everything else is retained.
	for name := range values {
		for _, prefix := range []string{filepath.Join(deploymentRoot, "state"), filepath.Join(deploymentRoot, "versions", f.intent.plan.Active.ID), filepath.Join("owned-incoming", f.intent.plan.Active.Identity.ManifestSHA256)} {
			if name == prefix || strings.HasPrefix(name, prefix+string(os.PathSeparator)) {
				delete(values, name)
			}
		}
	}
	raw, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func exerciseOwnedRemovalFileTransactions(t *testing.T, privateBase string) {
	t.Helper()
	cases := []string{"complete", "intent-fault", "unlink-fault", "parent-sync-fault", "done-fault", "partial-intent", "partial-done", "wrong-journal", "journal-alias", "journal-hardlink", "journal-mode", "missing-unrecorded", "changed-file", "extra-file", "recreated-completed", "missing-other-pending", "parent-replaced", "cancelled"}
	if len(cases) != ownedRemovalFileCaseCount {
		t.Fatal("journal case count differs")
	}
	for _, kind := range cases {
		if !t.Run("protected-file-journal-"+kind, func(t *testing.T) {
			f := newOwnedRemovalTargetFixture(t, privateBase, true)
			retained := retainedRemovalFixtureSnapshot(t, f)
			actions, e := removalFileActions(f.intent.plan)
			if e != nil || len(actions) != 2 {
				t.Fatal(actions, e)
			}
			core := f.coreFile
			input := f.incomingFile
			journalPath := filepath.Join(f.base, deploymentRoot, "state", removalJournalName)
			ctx := context.Background()
			refusal := false
			fault := func(phase string) {
				t.Helper()
				f.store.observe = func(actual string) error {
					if actual == phase {
						return errors.New("owned injected file boundary")
					}
					return nil
				}
				got, e := f.intent.removeNextProtectedFileUsing(ctx, f.resolve)
				f.store.observe = nil
				if e == nil || got != (removalFileProgress{}) {
					t.Fatal("injected boundary not refused", got, e)
				}
			}
			writeJournal := func(raw []byte) {
				t.Helper()
				if e := os.WriteFile(journalPath, raw, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Chown(journalPath, 0, 0); e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "complete":
			case "intent-fault":
				fault("removal-file-intent-durable")
			case "unlink-fault":
				fault("removal-file-unlinked")
			case "parent-sync-fault":
				fault("removal-file-parent-durable")
			case "done-fault":
				fault("removal-file-done-durable")
			case "partial-intent":
				seed := removalJournalSeed(f.intent.fence)
				j, _ := decodeRemovalJournal(nil, seed, 2)
				line, _ := nextRemovalJournalLine(seed, j)
				writeJournal(line[:len(line)/2])
			case "partial-done":
				fault("removal-file-unlinked")
				raw, _, j, e := readRemovalJournalAt(f.store.current, 0, removalJournalSeed(f.intent.fence), 2)
				if e != nil {
					t.Fatal(e)
				}
				line, _ := nextRemovalJournalLine(removalJournalSeed(f.intent.fence), j)
				writeJournal(append(raw, line[:len(line)/2]...))
			case "wrong-journal":
				writeJournal([]byte("{}\n"))
				refusal = true
			case "journal-alias":
				if e := os.Symlink(filepath.Join(f.base, "private-profile"), journalPath); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "journal-hardlink":
				if e := os.Link(filepath.Join(f.base, "private-profile"), journalPath); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "journal-mode":
				writeJournal(nil)
				if e := os.Chmod(journalPath, 0660); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "missing-unrecorded":
				if e := os.Remove(core); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "changed-file":
				if e := os.WriteFile(core, []byte("changed core bytes"), 0644); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "extra-file":
				if e := os.WriteFile(filepath.Join(f.incomingRoot, "unknown-file"), []byte("keep"), 0644); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "recreated-completed":
				if _, e := f.intent.removeNextProtectedFileUsing(ctx, f.resolve); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(core, []byte("owned core bytes"), 0644); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "missing-other-pending":
				fault("removal-file-intent-durable")
				if e := os.Remove(input); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "parent-replaced":
				if e := os.Rename(f.incomingParent, f.incomingParent+"-old"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(f.incomingParent, 0755); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
				refusal = true
			}
			if refusal {
				before := ownedRemovalTargetSnapshot(t, f.base)
				got, e := f.intent.removeNextProtectedFileUsing(ctx, f.resolve)
				if e == nil || got != (removalFileProgress{}) {
					t.Fatal("unsafe transaction accepted", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("refusal modified owned data")
				}
				return
			}
			// Release both leases and revalidate from durable metadata, never an
			// in-memory success marker, before every interrupted retry.
			reopenOwnedRemovalFileIntent(t, f)
			for i := 0; i < 3; i++ {
				got, e := f.intent.removeNextProtectedFileUsing(ctx, f.resolve)
				if e != nil {
					t.Fatal("file retry failed", got, e)
				}
				if got.total != 2 || got.completed < 1 || got.completed > 2 {
					t.Fatal("wrong durable progress", got)
				}
				if got.completed == 2 {
					break
				}
			}
			reopenOwnedRemovalFileIntent(t, f)
			before := ownedRemovalTargetSnapshot(t, f.base)
			got, e := f.intent.removeNextProtectedFileUsing(ctx, f.resolve)
			if e != nil || got != (removalFileProgress{2, 2}) {
				t.Fatal("completed retry failed", got, e)
			}
			if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
				t.Fatal("completed retry changed data")
			}
			for _, name := range []string{core, input} {
				if _, e := os.Lstat(name); !os.IsNotExist(e) {
					t.Fatal("journaled file remains", name, e)
				}
			}
			if !bytes.Equal(retained, retainedRemovalFixtureSnapshot(t, f)) {
				t.Fatal("file removal changed retained data")
			}
		}) {
			t.Fatalf("owned file journal case failed: %s", kind)
		}
	}
}
