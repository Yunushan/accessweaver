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

func exerciseOwnedQuarantinedAppKilledProcesses(t *testing.T, privateBase string) []map[string]any {
	t.Helper()
	if !ownedRemovalKillHost() {
		t.Fatal("app SIGKILL fixture requires opted-in disposable hosted root")
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	records := []map[string]any{}
	for _, target := range []string{"file", "nested-directory", "quarantined-root"} {
		phases := removalAppFileKillPhases
		initialCompleted := 6
		if target != "file" {
			phases = removalAppDirectoryKillPhases
			initialCompleted = 7
			if target == "quarantined-root" {
				initialCompleted = 8
			}
		}
		for index, phase := range phases {
			if !t.Run("quarantined-app-sigkill-"+target+"-"+phase, func(t *testing.T) {
				f := newOwnedRemovalTargetFixture(t, privateBase, true, true)
				retained := retainedRemovalQuarantineSnapshot(t, f)
				if e := f.intent.quarantinePublicAppUsing(context.Background(), f.resolve); e != nil {
					t.Fatal(e)
				}
				for i := 1; i <= 6; i++ {
					got, e := f.intent.removeNextQuarantinedProtectedObjectUsing(context.Background(), f.resolve, false)
					if e != nil || got != (removalProgress{i, 6}) {
						t.Fatal("app SIGKILL protected prefix failed", got, e)
					}
				}
				for i := 7; i <= initialCompleted; i++ {
					got, e := f.intent.removeNextQuarantinedAppObjectUsing(context.Background(), f.resolve)
					if e != nil || got != (removalProgress{i, 9}) {
						t.Fatal("app SIGKILL preparation failed", got, e)
					}
				}
				root := filepath.Join(f.base, deploymentRoot, "state", removalQuarantineName)
				object := filepath.Join(root, "owned-public-dir", "owned-public")
				if target == "nested-directory" {
					object = filepath.Dir(object)
				} else if target == "quarantined-root" {
					object = root
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
					t.Fatal("app child did not terminate at boundary", e, contextError, string(output.data))
				}
				status, ok := exit.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || bytes.Count(output.data, []byte("OWNED-REMOVAL-SIGKILL "+phase+"\n")) != 1 {
					t.Fatal("app child signal/marker differs", e, string(output.data))
				}
				parent, e := os.Open(f.base)
				if e != nil {
					t.Fatal(e)
				}
				f.intent, e = openRemovalIntentAt(parent, 0, identity, seal)
				if e != nil {
					t.Fatal("app killed-child reopen failed", e)
				}
				f.store = f.intent.store
				actions, e := removalAllActions(f.intent.plan)
				if e != nil || len(actions) != 10 {
					t.Fatal(actions, e)
				}
				raw, _, journal, e := readRemovalJournalAt(f.store.current, 0, removalJournalSeed(f.intent.fence), len(actions))
				done := index == 3
				completed := initialCompleted + intBool(done)
				if e != nil || journal.completed != completed || journal.pending == done || journal.entries != 2*completed+intBool(!done) || len(journal.tail) != 0 {
					t.Fatal("app killed-child journal differs", journal, e)
				}
				_, objectError := os.Lstat(object)
				if index == 0 && objectError != nil || index != 0 && !os.IsNotExist(objectError) {
					t.Fatal("app killed-child object presence differs", objectError)
				}
				if _, e := os.Lstat(f.publicRoot); !os.IsNotExist(e) {
					t.Fatal("public app name present during app removal", e)
				}
				if e := f.intent.verifyRemainingObjects(context.Background(), f.resolve, actions, journal); e != nil {
					t.Fatal("app killed-child remaining objects differ", e)
				}
				completeOwnedQuarantinedApp(t, f)
				reopenOwnedRemovalFileIntent(t, f)
				before := ownedRemovalTargetSnapshot(t, f.base)
				got, e := f.intent.removeNextQuarantinedAppObjectUsing(context.Background(), f.resolve)
				if e != nil || got != (removalProgress{9, 9}) {
					t.Fatal("app killed-child completion not idempotent", got, e)
				}
				if e := f.intent.quarantinePublicAppUsing(context.Background(), f.resolve); e != nil {
					t.Fatal("quarantine completion lost after killed app removal", e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) || !bytes.Equal(retained, retainedRemovalQuarantineSnapshot(t, f)) {
					t.Fatal("app killed-child changed retained data")
				}
				records = append(records, map[string]any{"target": target, "phase": phase, "signal": int(status.Signal()), "elapsedMilliseconds": elapsed, "timedOut": contextError != nil, "journalSHA256AtTermination": removalDigest(raw), "completedActionsAtTermination": journal.completed, "pendingAtTermination": journal.pending, "objectPresentAtTermination": objectError == nil, "completedObjectsAfterRetry": got.completed, "bothLeasesReacquired": true, "completedRetryIdempotent": true, "retainedDataPreserved": true, "passed": true})
			}) {
				t.Fatalf("app SIGKILL case failed: %s %s", target, phase)
			}
		}
	}
	if len(records) != 12 {
		t.Fatal("app SIGKILL case extent differs")
	}
	return records
}
