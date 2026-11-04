//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Only the trusted source-built test child executes, inside the same opted-in
// disposable root fixture as the file/directory SIGKILL cases. No installed
// payload is executed. Child environment deliberately excludes credentials.
func exerciseOwnedRemovalKilledQuarantine(t *testing.T, privateBase string) []map[string]any {
	t.Helper()
	if !ownedRemovalKillHost() {
		t.Fatal("quarantine SIGKILL requires opted-in disposable hosted root")
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	records := []map[string]any{}
	for index, phase := range removalQuarantineKillPhases {
		if !t.Run("public-quarantine-sigkill-"+phase, func(t *testing.T) {
			f := newOwnedRemovalTargetFixture(t, privateBase, true)
			retained := retainedRemovalQuarantineSnapshot(t, f)
			publicBefore, e := os.Lstat(f.publicRoot)
			if e != nil {
				t.Fatal(e)
			}
			identity, seal := f.intent.fence.Target.Identity, f.intent.fence.DesktopRecordSHA256
			if e := f.intent.Close(); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
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
				t.Fatal("quarantine child did not terminate at boundary", e, contextError, string(output.data))
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || bytes.Count(output.data, []byte("OWNED-REMOVAL-SIGKILL "+phase+"\n")) != 1 {
				t.Fatal("quarantine child signal/marker differs", e)
			}
			parent, e := os.Open(f.base)
			if e != nil {
				t.Fatal(e)
			}
			f.intent, e = openRemovalIntentAt(parent, 0, identity, seal)
			if e != nil {
				t.Fatal("quarantine killed-child reopen failed", e)
			}
			f.store = f.intent.store
			raw, _, journal, e := readRemovalQuarantineAt(f.store.current, 0, f.intent.fence, f.intent.plan)
			done := index == 3
			completed := intBool(done)
			if e != nil || journal.completed != completed || journal.pending == done || journal.entries != 1+completed || len(journal.tail) != 0 || journal.validBytes != len(raw) {
				t.Fatal("quarantine killed-child journal differs", journal, e)
			}
			movedPath := filepath.Join(f.base, deploymentRoot, "state", removalQuarantineName)
			sourceInfo, sourceError := os.Lstat(f.publicRoot)
			movedInfo, movedError := os.Lstat(movedPath)
			sourcePresent := index == 0
			if sourcePresent && sourceError != nil || !sourcePresent && !os.IsNotExist(sourceError) || sourcePresent && !os.IsNotExist(movedError) || !sourcePresent && movedError != nil {
				t.Fatal("quarantine killed-child app locations differ", sourceError, movedError)
			}
			observed := sourceInfo
			if !sourcePresent {
				observed = movedInfo
			}
			if observed == nil || !os.SameFile(publicBefore, observed) {
				t.Fatal("quarantine moved a different app vnode")
			}
			_, _, protected, e := readRemovalJournalAt(f.store.current, 0, removalJournalSeed(f.intent.fence), 6)
			if e != nil || protected.entries != 0 || len(protected.tail) != 0 {
				t.Fatal("protected payload progress before quarantine completion", protected, e)
			}
			// Prove zero payload loss from actual objects, not only an empty log.
			for _, root := range f.intent.plan.Roots {
				if root.Kind != "public" || sourcePresent {
					if e := f.intent.verifyIntactTarget(context.Background(), root, f.resolve); e != nil {
						t.Fatal("killed quarantine changed an intact target", e)
					}
				}
			}
			if !sourcePresent {
				if e := f.intent.verifyQuarantineTree(context.Background()); e != nil {
					t.Fatal("killed quarantine tree differs", e)
				}
			}
			if !done {
				before := ownedRemovalTargetSnapshot(t, f.base)
				if got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(context.Background(), f.resolve, false); e == nil || got != (removalProgress{}) {
					t.Fatal("incomplete killed quarantine authorized deletion", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("incomplete quarantine refusal changed data")
				}
			}
			if e := f.intent.quarantinePublicAppUsing(context.Background(), f.resolve); e != nil {
				t.Fatal("quarantine killed-child retry failed", e)
			}
			reopenOwnedRemovalFileIntent(t, f)
			if e := f.intent.quarantinePublicAppUsing(context.Background(), f.resolve); e != nil {
				t.Fatal("quarantine retry after reopen failed", e)
			}
			for next := 1; next <= 6; next++ {
				got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(context.Background(), f.resolve, false)
				if e != nil || got != (removalProgress{next, 6}) {
					t.Fatal("quarantine killed-child protected completion failed", got, e)
				}
			}
			reopenOwnedRemovalFileIntent(t, f)
			before := ownedRemovalTargetSnapshot(t, f.base)
			if e := f.intent.quarantinePublicAppUsing(context.Background(), f.resolve); e != nil {
				t.Fatal("quarantine completed retry failed", e)
			}
			got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(context.Background(), f.resolve, false)
			if e != nil || got != (removalProgress{6, 6}) {
				t.Fatal("quarantine protected completion not idempotent", got, e)
			}
			if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) || !bytes.Equal(retained, retainedRemovalQuarantineSnapshot(t, f)) {
				t.Fatal("quarantine killed-child changed retained data")
			}
			if e := f.intent.verifyQuarantineTree(context.Background()); e != nil {
				t.Fatal("retained quarantined app changed", e)
			}
			records = append(records, map[string]any{"phase": phase, "signal": int(status.Signal()), "elapsedMilliseconds": elapsed, "timedOut": contextError != nil, "journalSHA256AtTermination": removalDigest(raw), "completedQuarantineActionsAtTermination": completed, "pendingAtTermination": journal.pending, "publicAppPresentAtTermination": sourceError == nil, "quarantinedAppPresentAtTermination": movedError == nil, "protectedObjectsRemovedAtTermination": 0, "completedProtectedObjectsAfterRetry": got.completed, "bothLeasesReacquired": true, "completedRetryIdempotent": true, "retainedDataPreserved": true, "passed": true})
		}) {
			t.Fatalf("owned quarantine SIGKILL case failed: %s", phase)
		}
	}
	if len(records) != 4 {
		t.Fatal("quarantine killed-child case extent differs")
	}
	return records
}
