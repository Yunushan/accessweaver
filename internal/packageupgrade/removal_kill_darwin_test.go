//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

const removalKillBaseEnv = "ACCESSWEAVER_OWNED_REMOVAL_KILL_BASE"
const removalKillPhaseEnv = "ACCESSWEAVER_OWNED_REMOVAL_KILL_PHASE"

var removalAppFileKillPhases = []string{
	"removal-app-file-intent-durable", "removal-app-file-unlinked", "removal-app-file-parent-durable", "removal-app-file-done-durable",
}
var removalAppDirectoryKillPhases = []string{
	"removal-app-directory-intent-durable", "removal-app-directory-unlinked", "removal-app-directory-parent-durable", "removal-app-directory-done-durable",
}

var removalQuarantineKillPhases = []string{
	"removal-quarantine-intent-durable",
	"removal-quarantine-renamed",
	"removal-quarantine-parents-durable",
	"removal-quarantine-done-durable",
}

var removalDirectoryKillPhases = []string{
	"removal-directory-intent-durable",
	"removal-directory-unlinked",
	"removal-directory-parent-durable",
	"removal-directory-done-durable",
}

var removalKillPhases = []string{
	"removal-file-intent-durable",
	"removal-file-unlinked",
	"removal-file-parent-durable",
	"removal-file-done-durable",
}

func ownedRemovalKillHost() bool {
	return os.Geteuid() == 0 && os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST") == "1" &&
		os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" && os.Getenv("RUNNER_OS") == "macOS"
}

// This is a test-only path. It accepts exactly the new root-owned fixture
// capsule shape created by the guarded parent test. Every component below
// sticky /private/tmp opens without following links and requires root ownership,
// protected permissions and the normal APFS/ACL checks.
func openOwnedRemovalKillCapsule(base string) (result *os.File, failure error) {
	if filepath.Clean(base) != base || !strings.HasPrefix(base, "/private/tmp/") {
		return nil, errors.New("invalid killed-child fixture path")
	}
	parts := strings.Split(strings.TrimPrefix(base, "/private/tmp/"), "/")
	if len(parts) != 3 || !regexp.MustCompile("^accessweaver-deployment-[0-9]+$").MatchString(parts[0]) || parts[1] != "schema2-bridge" || !regexp.MustCompile("^targets-[0-9]+$").MatchString(parts[2]) {
		return nil, errors.New("unrecognized killed-child capsule")
	}
	private, e := darwintrust.OpenRootDirectory("/private")
	if e != nil {
		return nil, e
	}
	fd, e := unix.Openat(int(private.Fd()), "tmp", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	closeErr := private.Close()
	if e != nil || closeErr != nil {
		if e == nil {
			unix.Close(fd)
		}
		return nil, errors.Join(e, closeErr)
	}
	current := os.NewFile(uintptr(fd), "fixed-sticky-tmp")
	info, e := current.Stat()
	if e == nil {
		st := info.Sys().(*syscall.Stat_t)
		if st.Uid != 0 || st.Mode&07777 != 01777 {
			e = errors.New("temporary parent protection differs")
		}
	}
	if e == nil {
		e = darwintrust.CheckPersistent(current)
	}
	if e != nil {
		return nil, errors.Join(e, current.Close())
	}
	for i, part := range parts {
		next, e := darwintrust.OpenDirectoryAt(current, part, 0)
		closeErr := current.Close()
		if e != nil || closeErr != nil {
			if next != nil {
				closeErr = errors.Join(closeErr, next.Close())
			}
			return nil, errors.Join(e, closeErr)
		}
		current = next
		info, e := current.Stat()
		mode := os.FileMode(0700)
		if i == 1 {
			mode = 0755
		}
		if e == nil && info.Mode().Perm() != mode {
			e = errors.New("owned capsule mode differs")
		}
		if e != nil {
			return nil, errors.Join(e, current.Close())
		}
	}
	return current, nil
}

// Only the parent root fixture selects this test and supplies the private
// capsule and one fixed phase. The child has no inherited workflow credentials.
// SIGKILL prevents Go defers, store.Close and ordinary error handling.
func TestDarwinRemovalFileKilledChild(t *testing.T) {
	base, phase := os.Getenv(removalKillBaseEnv), os.Getenv(removalKillPhaseEnv)
	if base == "" && phase == "" {
		t.Skip("guarded child only")
	}
	if !ownedRemovalKillHost() {
		t.Fatal("killed child requires an opted-in disposable hosted root fixture")
	}
	known := phase == "removal-handoff-stage-record" || phase == "removal-handoff-reserved" || phase == "removal-handoff-exchanged"
	allowedPhases := append(append(append(append(append([]string{}, removalKillPhases...), removalDirectoryKillPhases...), removalQuarantineKillPhases...), removalAppFileKillPhases...), removalAppDirectoryKillPhases...)
	for _, allowed := range allowedPhases {
		if phase == allowed {
			known = true
		}
	}
	preparing := false
	for _, allowed := range removalPreparationKillPhases {
		if phase == allowed {
			known, preparing = true, true
		}
	}
	if !known {
		t.Fatal("unknown killed-child phase")
	}
	parent, e := openOwnedRemovalKillCapsule(base)
	if e != nil {
		t.Fatal(e)
	}
	if preparing {
		runOwnedRemovalPreparationKilledChild(t, parent, base, phase)
		t.Fatal("preparation child returned without its kill boundary")
	}
	identity := deploymentFixtureSlot(1, "0.1.1-alpha").Identity
	intent, e := openRemovalIntentAt(parent, 0, identity, removalDigest([]byte("owned synthetic registration")))
	if e != nil {
		t.Fatal(e)
	}
	defer intent.Close()
	fixture := &ownedRemovalTargetFixture{base: base, store: intent.store, intent: intent}
	kill := ownedRemovalKillObserver(phase)
	intent.store.observe = kill
	if strings.HasPrefix(phase, "removal-handoff-") {
		intent.store.observe = func(actual string) error {
			if actual == phase {
				requireOwnedRemovalHandoffLeases(t, base)
			}
			return kill(actual)
		}
	}
	if strings.HasPrefix(phase, "removal-app-") {
		_, e = intent.removeNextQuarantinedAppObjectUsing(context.Background(), fixture.resolve)
	} else if strings.HasPrefix(phase, "removal-quarantine-") {
		e = intent.quarantinePublicAppUsing(context.Background(), fixture.resolve)
	} else if strings.HasPrefix(phase, "removal-handoff-") {
		_, e = intent.finalizeRemovalUsing(context.Background(), fixture.resolve)
	} else if strings.HasPrefix(phase, "removal-directory-") {
		_, e = intent.removeNextProtectedObjectUsing(context.Background(), fixture.resolve, false)
	} else {
		_, e = intent.removeNextProtectedFileUsing(context.Background(), fixture.resolve)
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Fatal("owned child completed without reaching its kill boundary")
}

func ownedRemovalKillObserver(phase string) func(string) error {
	return func(actual string) error {
		if actual != phase {
			return nil
		}
		fmt.Println("OWNED-REMOVAL-SIGKILL " + phase)
		if e := unix.Kill(os.Getpid(), unix.SIGKILL); e != nil {
			return e
		}
		// A self-signal can be delivered to another thread. Keep this exact
		// boundary and both leases until delivery instead of racing an ordinary
		// test exit. Go's runtime SignalExitStatus fixture uses the same wait.
		// The parent still requires actual SIGKILL, one marker and no timeout.
		time.Sleep(time.Second)
		return errors.New("SIGKILL did not terminate the owned child")
	}
}

// The trusted source-built test binary is the only executed child. No installed
// product, app bundle, core payload or public launcher runs as root.
func exerciseOwnedRemovalKilledProcesses(t *testing.T, privateBase string) []map[string]any {
	return exerciseOwnedRemovalKillCases(t, privateBase, false)
}
func exerciseOwnedRemovalKilledDirectories(t *testing.T, privateBase string) []map[string]any {
	return exerciseOwnedRemovalKillCases(t, privateBase, true)
}
func exerciseOwnedRemovalKillCases(t *testing.T, privateBase string, directory bool) []map[string]any {
	t.Helper()
	if !ownedRemovalKillHost() {
		t.Fatal("process-kill fixture requires opted-in disposable hosted root")
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	phases, targets := removalKillPhases, []string{"file"}
	if directory {
		phases, targets = removalDirectoryKillPhases, []string{"nested-directory", "protected-root"}
	}
	records := []map[string]any{}
	for _, target := range targets {
		for _, phase := range phases {
			if !t.Run("protected-sigkill-"+target+"-"+phase, func(t *testing.T) {
				f := newOwnedRemovalTargetFixture(t, privateBase, true)
				retainedSnapshot := func() []byte {
					if directory {
						return retainedRemovalDirectorySnapshot(t, f)
					}
					return retainedRemovalFixtureSnapshot(t, f)
				}
				retained := retainedSnapshot()
				initialCompleted, journalActions := 0, 2
				objectPath := f.coreFile
				if directory {
					completeOwnedRemovalFiles(t, f)
					initialCompleted, journalActions = 2, 6
					objectPath = filepath.Dir(f.coreFile)
					if target == "protected-root" {
						got, e := f.intent.removeNextProtectedObjectUsing(context.Background(), f.resolve, false)
						if e != nil || got.completed != 3 {
							t.Fatal("root kill precondition failed", got, e)
						}
						initialCompleted = 3
						objectPath = filepath.Dir(objectPath)
					}
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
				e := command.Run()
				elapsed := time.Since(started).Milliseconds()
				contextError := ctx.Err()
				cancel()
				var exit *exec.ExitError
				if contextError != nil || !errors.As(e, &exit) {
					t.Fatal("owned child did not terminate at its boundary", e, contextError, string(output.data))
				}
				status, ok := exit.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || bytes.Count(output.data, []byte("OWNED-REMOVAL-SIGKILL "+phase+"\n")) != 1 {
					t.Fatal("owned child signal/marker differs", e, string(output.data))
				}
				parent, e := os.Open(f.base)
				if e != nil {
					t.Fatal(e)
				}
				f.intent, e = openRemovalIntentAt(parent, 0, identity, seal)
				if e != nil {
					t.Fatal("killed-child reopen failed", e)
				}
				f.store = f.intent.store
				journalRaw, _, journal, e := readRemovalJournalAt(f.store.current, 0, removalJournalSeed(f.intent.fence), journalActions)
				expectedCompleted := initialCompleted
				done := strings.HasSuffix(phase, "-done-durable")
				if done {
					expectedCompleted++
				}
				if e != nil || journal.completed != expectedCompleted || journal.pending == done || journal.entries != 2*expectedCompleted+intBool(!done) {
					t.Fatal("killed-child progress differs", journal, e)
				}
				_, statErr := os.Lstat(objectPath)
				present := strings.HasSuffix(phase, "-intent-durable")
				if present && statErr != nil || !present && !os.IsNotExist(statErr) {
					t.Fatal("child target state differs", target, statErr)
				}
				if directory {
					completeOwnedRemovalObjects(t, f)
				} else {
					for i := 0; i < 2; i++ {
						got, e := f.intent.removeNextProtectedFileUsing(context.Background(), f.resolve)
						if e != nil {
							t.Fatal("killed-child retry failed", got, e)
						}
						if got.completed == 2 {
							break
						}
					}
				}
				reopenOwnedRemovalFileIntent(t, f)
				before := ownedRemovalTargetSnapshot(t, f.base)
				var got removalProgress
				if directory {
					got, e = f.intent.removeNextProtectedObjectUsing(context.Background(), f.resolve, false)
				} else {
					got, e = f.intent.removeNextProtectedFileUsing(context.Background(), f.resolve)
				}
				expectedTotal := 2
				if directory {
					expectedTotal = 6
				}
				if e != nil || got != (removalProgress{expectedTotal, expectedTotal}) {
					t.Fatal("killed-child completion differs", got, e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) || !bytes.Equal(retained, retainedSnapshot()) {
					t.Fatal("killed-child retry changed retained data")
				}
				record := map[string]any{"target": target, "phase": phase, "signal": int(status.Signal()), "elapsedMilliseconds": elapsed, "timedOut": contextError != nil, "journalSHA256AtTermination": removalDigest(journalRaw), "completedActionsAtTermination": journal.completed, "pendingAtTermination": journal.pending, "bothLeasesReacquired": true, "completedRetryIdempotent": true, "retainedDataPreserved": true, "passed": true}
				if directory {
					record["directoryPresentAtTermination"] = statErr == nil
					record["completedObjectsAfterRetry"] = got.completed
				} else {
					record["filePresentAtTermination"] = statErr == nil
					record["completedFilesAfterRetry"] = got.completed
				}
				records = append(records, record)
			}) {
				t.Fatalf("owned SIGKILL case failed: %s %s", target, phase)
			}
		}
	}
	return records
}
func intBool(value bool) int {
	if value {
		return 1
	}
	return 0
}

type ownedRemovalKillOutput struct{ data []byte }

func (w *ownedRemovalKillOutput) Write(data []byte) (int, error) {
	if len(w.data)+len(data) > 4096 {
		return 0, errors.New("owned child output exceeds bound")
	}
	w.data = append(w.data, data...)
	return len(data), nil
}

// Invalid selectors refuse before opening any directory. The normal package
// tests never opt into a child or mutate a fixture.
func TestDarwinRemovalKilledChildPathRefusals(t *testing.T) {
	for _, base := range []string{"/", "/tmp/accessweaver-deployment-1/schema2-bridge/targets-1", "/private/tmp/other-1/schema2-bridge/targets-1", "/private/tmp/accessweaver-deployment-1/other/targets-1", "/private/tmp/accessweaver-deployment-1/schema2-bridge/other-1", "/private/tmp/accessweaver-deployment-1/schema2-bridge/targets-1/child", "/private/tmp/accessweaver-deployment-1/schema2-bridge/../targets-1", "/private/tmp/accessweaver-deployment-x/schema2-bridge/targets-1", "/private/tmp/accessweaver-deployment-1/schema2-bridge/targets-x"} {
		file, e := openOwnedRemovalKillCapsule(base)
		if file != nil {
			file.Close()
			t.Fatal("invalid selector opened a capsule")
		}
		if e == nil {
			t.Fatal("invalid selector accepted")
		}
	}
}
