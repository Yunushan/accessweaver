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
	"syscall"
	"testing"
)

const ownedRemovalQuarantineCaseCount = 28

func retainedRemovalQuarantineSnapshot(t *testing.T, f *ownedRemovalTargetFixture) []byte {
	t.Helper()
	values := map[string]string{}
	if e := json.Unmarshal(retainedRemovalFixtureSnapshot(t, f), &values); e != nil {
		t.Fatal(e)
	}
	for name := range values {
		prefix := filepath.Join("owned-applications", "AccessWeaver.app")
		if name == "owned-applications" || name == prefix || strings.HasPrefix(name, prefix+string(os.PathSeparator)) {
			delete(values, name)
		}
	}
	raw, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func exerciseOwnedRemovalQuarantine(t *testing.T, privateBase string) {
	t.Helper()
	cases := []string{"complete", "intent-fault", "rename-fault", "parents-fault", "done-fault", "completed-file-sync-refusal", "completed-state-sync-refusal", "partial-intent", "partial-done", "wrong-journal", "journal-alias", "journal-hardlink", "journal-mode", "unrecorded-quarantine", "missing-public", "changed-public", "recreated-public", "changed-quarantine", "missing-quarantine", "parent-replaced", "raced-file", "raced-symlink", "raced-directory", "raced-conflict", "destination-conflict", "cancelled", "deletion-requires-quarantine", "partial-intent-with-entry"}
	if len(cases) != ownedRemovalQuarantineCaseCount {
		t.Fatal("quarantine case count differs")
	}
	for _, kind := range cases {
		if !t.Run("public-quarantine-"+kind, func(t *testing.T) {
			f := newOwnedRemovalTargetFixture(t, privateBase, true)
			retained := retainedRemovalQuarantineSnapshot(t, f)
			state := filepath.Join(f.base, deploymentRoot, "state")
			journalPath := filepath.Join(state, removalQuarantineJournalName)
			movedPath := filepath.Join(state, removalQuarantineName)
			ctx := context.Background()
			fault := func(phase string) {
				t.Helper()
				f.store.observe = func(actual string) error {
					if phase == actual {
						return errors.New("owned injected quarantine boundary")
					}
					return nil
				}
				e := f.intent.quarantinePublicAppUsing(ctx, f.resolve)
				f.store.observe = nil
				if e == nil {
					t.Fatal("quarantine boundary not refused")
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
			complete := func() {
				t.Helper()
				if e := f.intent.quarantinePublicAppUsing(ctx, f.resolve); e != nil {
					t.Fatal(e)
				}
			}
			partial := func() {
				t.Helper()
				raw, _, j, e := readRemovalQuarantineAt(f.store.current, 0, f.intent.fence, f.intent.plan)
				if e != nil {
					t.Fatal(e)
				}
				info, e := f.store.current.Stat()
				if e != nil {
					t.Fatal(e)
				}
				st := info.Sys().(*syscall.Stat_t)
				seed, e := removalQuarantineSeed(f.intent.fence, f.intent.plan, uint64(st.Dev), st.Ino)
				if e != nil {
					t.Fatal(e)
				}
				line, e := nextRemovalJournalLine(seed, j)
				if e != nil {
					t.Fatal(e)
				}
				write(journalPath, append(raw, line[:len(line)/2]...), 0600)
			}
			refusal := false
			switch kind {
			case "complete":
			case "intent-fault":
				fault("removal-quarantine-intent-durable")
			case "rename-fault":
				fault("removal-quarantine-renamed")
			case "parents-fault":
				fault("removal-quarantine-parents-durable")
			case "done-fault":
				fault("removal-quarantine-done-durable")
			case "partial-intent":
				partial()
			case "partial-done":
				fault("removal-quarantine-renamed")
				partial()
			case "wrong-journal":
				write(journalPath, []byte("{}\n"), 0600)
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
				write(journalPath, nil, 0660)
				refusal = true
			case "unrecorded-quarantine":
				if e := os.Mkdir(movedPath, 0755); e != nil {
					t.Fatal(e)
				}
				if e := os.Chown(movedPath, 0, 0); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "missing-public":
				if e := os.Rename(f.publicRoot, filepath.Join(f.base, "retained-app")); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "changed-public":
				write(f.publicFile, []byte("keep changed public bytes"), 0644)
				refusal = true
			case "recreated-public":
				complete()
				if e := os.Mkdir(f.publicRoot, 0755); e != nil {
					t.Fatal(e)
				}
				if e := os.Chown(f.publicRoot, 0, 0); e != nil {
					t.Fatal(e)
				}
				write(filepath.Join(f.publicRoot, "private"), []byte("keep new public object"), 0600)
				refusal = true
			case "changed-quarantine":
				complete()
				write(filepath.Join(movedPath, "owned-public"), []byte("keep changed quarantine"), 0644)
				refusal = true
			case "missing-quarantine":
				complete()
				if e := os.Rename(movedPath, filepath.Join(f.base, "retained-app")); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "parent-replaced":
				apps := filepath.Dir(f.publicRoot)
				if e := os.Rename(apps, filepath.Join(f.base, "retained-applications")); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(apps, 0775); e != nil {
					t.Fatal(e)
				}
				if e := os.Chown(apps, 0, 80); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(apps, 0775); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				refusal = true
			case "partial-intent-with-entry":
				partial()
				if e := os.Rename(f.publicRoot, movedPath); e != nil {
					t.Fatal(e)
				}
				refusal = true
			case "deletion-requires-quarantine":
				before := ownedRemovalTargetSnapshot(t, f.base)
				if got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, false); e == nil || got != (removalProgress{}) {
					t.Fatal("deletion accepted before quarantine", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("missing-quarantine refusal mutated fixture")
				}
			case "completed-file-sync-refusal", "completed-state-sync-refusal":
				phase := "removal-quarantine-before-file-sync"
				if kind == "completed-state-sync-refusal" {
					phase = "removal-quarantine-before-state-sync"
				}
				f.store.observe = func(actual string) error {
					if actual == phase {
						_, _, j, e := readRemovalQuarantineAt(f.store.current, 0, f.intent.fence, f.intent.plan)
						if e != nil {
							return e
						}
						if j.completed == 1 {
							return errors.New("owned completion synchronization unavailable")
						}
					}
					return nil
				}
				if e := f.intent.quarantinePublicAppUsing(ctx, f.resolve); e == nil {
					t.Fatal("completion synchronization failure accepted")
				}
				f.store.observe = nil
				reopenOwnedRemovalFileIntent(t, f)
				f.store.observe = func(actual string) error {
					if actual == phase {
						return errors.New("owned synchronization still unavailable")
					}
					return nil
				}
				if e := f.intent.quarantinePublicAppUsing(ctx, f.resolve); e == nil {
					t.Fatal("readable completion acknowledged without sync")
				}
				if got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, false); e == nil || got != (removalProgress{}) {
					t.Fatal("payload deletion accepted unsynced quarantine", got, e)
				}
				f.store.observe = nil
			case "raced-file", "raced-symlink", "raced-directory", "raced-conflict", "destination-conflict":
				kept := filepath.Join(f.base, "retained-original-app")
				var unknown os.FileInfo
				var conflict os.FileInfo
				f.store.observe = func(phase string) error {
					if phase == "removal-quarantine-before-rename" {
						if kind == "destination-conflict" {
							write(movedPath, []byte("keep destination conflict"), 0600)
							var e error
							unknown, e = os.Lstat(movedPath)
							return e
						}
						if e := os.Rename(f.publicRoot, kept); e != nil {
							return e
						}
						if kind == "raced-symlink" {
							if e := os.Symlink(filepath.Join(f.base, "private-profile"), f.publicRoot); e != nil {
								return e
							}
						} else if kind == "raced-file" {
							write(f.publicRoot, []byte("keep raced file"), 0600)
						} else {
							if e := os.Mkdir(f.publicRoot, 0755); e != nil {
								return e
							}
							if e := os.Chown(f.publicRoot, 0, 0); e != nil {
								return e
							}
							write(filepath.Join(f.publicRoot, "private"), []byte("keep raced directory"), 0600)
						}
						var e error
						unknown, e = os.Lstat(f.publicRoot)
						return e
					}
					if phase == "removal-quarantine-renamed" && kind == "raced-conflict" {
						write(f.publicRoot, []byte("keep new conflict"), 0600)
						var e error
						conflict, e = os.Lstat(f.publicRoot)
						return e
					}
					return nil
				}
				e := f.intent.quarantinePublicAppUsing(ctx, f.resolve)
				f.store.observe = nil
				if e == nil || unknown == nil {
					t.Fatal("raced entry was not refused", e)
				}
				unknownPath := f.publicRoot
				if kind == "raced-conflict" || kind == "destination-conflict" {
					unknownPath = movedPath
				}
				after, e := os.Lstat(unknownPath)
				if e != nil || !os.SameFile(unknown, after) {
					t.Fatal("unknown entry lost or replaced", e)
				}
				if conflict != nil {
					after, e = os.Lstat(f.publicRoot)
					if e != nil || !os.SameFile(conflict, after) {
						t.Fatal("public conflict replaced", e)
					}
				}
				if kind != "destination-conflict" {
					data, e := os.ReadFile(filepath.Join(kept, "owned-public"))
					if e != nil || string(data) != "owned public bytes" {
						t.Fatal("original app changed", e)
					}
				}
				for _, name := range []string{f.coreFile, f.incomingFile, filepath.Join(f.base, "private-profile")} {
					if _, e := os.Stat(name); e != nil {
						t.Fatal("retained data missing", e)
					}
				}
				before := ownedRemovalTargetSnapshot(t, f.base)
				if got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, false); e == nil || got != (removalProgress{}) {
					t.Fatal("deletion accepted raced quarantine", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("raced quarantine deletion refusal mutated fixture")
				}
				return
			}
			if refusal {
				before := ownedRemovalTargetSnapshot(t, f.base)
				if e := f.intent.quarantinePublicAppUsing(ctx, f.resolve); e == nil {
					t.Fatal("quarantine tamper/cancellation accepted")
				}
				if got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, false); e == nil || got != (removalProgress{}) {
					t.Fatal("deletion accepted refused quarantine", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("quarantine refusal mutated fixture")
				}
				return
			}
			reopenOwnedRemovalFileIntent(t, f)
			complete()
			reopenOwnedRemovalFileIntent(t, f)
			complete()
			if e := removalNameAbsentForFixture(f.publicRoot); e != nil {
				t.Fatal(e)
			}
			if e := f.intent.requirePublicQuarantine(ctx, f.resolve); e != nil {
				t.Fatal(e)
			}
			for i := 1; i <= 6; i++ {
				got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, false)
				if e != nil || got != (removalProgress{i, 6}) {
					t.Fatal("quarantined protected removal", got, e)
				}
			}
			got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(ctx, f.resolve, false)
			if e != nil || got != (removalProgress{6, 6}) {
				t.Fatal("quarantined completion not idempotent", got, e)
			}
			complete() // Quarantine completion remains idempotent after payload progress.
			if !bytes.Equal(retained, retainedRemovalQuarantineSnapshot(t, f)) {
				t.Fatal("quarantine/removal changed retained data")
			}
			if data, e := os.ReadFile(filepath.Join(movedPath, "owned-public")); e != nil || string(data) != "owned public bytes" {
				t.Fatal("quarantined app payload changed", e)
			}
		}) {
			t.FailNow()
		}
	}
}
func removalNameAbsentForFixture(name string) error {
	_, e := os.Lstat(name)
	if !errors.Is(e, os.ErrNotExist) {
		return errors.Join(e, errors.New("fixture public app still present"))
	}
	return nil
}
