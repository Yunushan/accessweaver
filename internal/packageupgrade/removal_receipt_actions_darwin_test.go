//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

func requireHostedReceiptFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST") != "1" {
		t.Skip("requires opted-in hosted macOS runner")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("receipt removal test requires a disposable hosted Mac")
	}
}

// Use real, uniquely named receipts for unsigned inert packages on the hosted
// VM. Both packages install only inert text under the fixture root. A second
// subject package adds one bounded postinstall script for the contention probe.
func TestDarwinRemovalReceiptToolReinstall(t *testing.T) {
	requireHostedReceiptFixture(t)
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil || !filepath.IsAbs(base) {
		t.Fatal("receipt fixture location unavailable", e)
	}
	root, e := darwintrust.OpenRootDirectory("/private/var/db/receipts")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := root.Close(); e != nil {
			t.Error(e)
		}
	})
	command := func(ctx context.Context, path string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		return cmd
	}
	run := func(path string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if e := command(ctx, path, args...).Run(); e != nil {
			t.Fatal("native receipt fixture command failed", e)
		}
	}
	const version = "1.0.0"
	const filename = "owned-receipt-fixture.txt"
	payload := []byte("inert receipt retirement fixture")
	makePackage := func(role, id string) (string, string) {
		t.Helper()
		source := filepath.Join(base, role+"-source")
		if e := os.Mkdir(source, 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(source, filename), payload, 0644); e != nil {
			t.Fatal(e)
		}
		dest := filepath.Join(base, role+"-installed")
		if e := os.Mkdir(dest, 0755); e != nil {
			t.Fatal(e)
		}
		pkg := filepath.Join(base, role+".pkg")
		run("/usr/bin/pkgbuild", "--root", source, "--identifier", id, "--version", version, "--install-location", dest, pkg)
		return pkg, dest
	}
	assertPairAbsent := func(id string) {
		t.Helper()
		for _, ext := range []string{".bom", ".plist"} {
			if _, _, e := readAt(root, id+ext, 4<<20); !darwintrust.IsReadAbsent(e) {
				t.Fatal("fixture receipt pair must be absent", e)
			}
		}
	}
	pairHash := func(id string) [2]string {
		t.Helper()
		var result [2]string
		for i, ext := range []string{".bom", ".plist"} {
			raw, st, e := readAt(root, id+ext, 4<<20)
			if e != nil || len(raw) == 0 || st.Mode&07777 != 0644 {
				t.Fatal("fixture receipt pair not readable", e)
			}
			result[i] = digest(raw)
		}
		return result
	}
	assertPayload := func(dest string) {
		t.Helper()
		data, e := os.ReadFile(filepath.Join(dest, filename))
		if e != nil || !bytes.Equal(data, payload) {
			t.Fatal("native receipt operation changed fixture payload", e)
		}
	}
	checkReceipt := func(id, dest string) {
		t.Helper()
		info, e := queryRemovalReceipt(context.Background(), "--pkg-info", id)
		if e != nil {
			t.Fatal(e)
		}
		if e = checkRemovalReceiptMetadata(info, removalReceiptExpectation{ID: id, Version: version, Location: dest}); e != nil {
			t.Fatal(e)
		}
		files, e := queryRemovalReceipt(context.Background(), "--files", id)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = checkRemovalReceiptPaths(files, []string{filename}); e != nil {
			t.Fatal(e)
		}
	}

	nonce, e := randomDeploymentName()
	if e != nil {
		t.Fatal(e)
	}
	id := desktopBundleID + ".registration." + digest([]byte(nonce))
	controlID := "org.accessweaver-tests.receipt." + nonce
	assertPairAbsent(id)
	assertPairAbsent(controlID)
	subject, dest := makePackage("subject", id)
	control, controlDest := makePackage("control", controlID)
	// Scrub just the two freshly checked IDs, including if Installer fails
	// after publishing a receipt.
	t.Cleanup(func() {
		for _, fixtureID := range []string{id, controlID} {
			if _, _, e := readAt(root, fixtureID+".plist", 4<<20); !darwintrust.IsReadAbsent(e) {
				run("/usr/sbin/pkgutil", "--forget", fixtureID)
			}
			assertPairAbsent(fixtureID)
		}
	})
	run("/usr/sbin/installer", "-pkg", control, "-target", "/")
	run("/usr/sbin/installer", "-pkg", subject, "-target", "/")
	controlHash := pairHash(controlID)
	_ = pairHash(id)
	checkReceipt(id, dest)
	if e = forgetRemovalReceipt(context.Background(), id); e != nil {
		t.Fatal(e)
	}
	assertPairAbsent(id)
	assertPayload(dest)
	if pairHash(controlID) != controlHash {
		t.Fatal("forgetting the subject changed the control receipt")
	}
	if e = os.Remove(filepath.Join(dest, filename)); e != nil {
		t.Fatal(e)
	}
	run("/usr/sbin/installer", "-pkg", subject, "-target", "/")
	_ = pairHash(id)
	checkReceipt(id, dest)
	assertPayload(dest)
	assertPayload(controlDest)
	if pairHash(controlID) != controlHash {
		t.Fatal("reinstalling the subject changed the control receipt")
	}

	// Reinstall the same package ID and hold Apple's postinstall phase open.
	// A standalone forget that succeeds in this window disproves relying on
	// Installer or pkgutil to serialize this removal interleaving.
	enter := filepath.Join(base, "postinstall-entered")
	release := filepath.Join(base, "postinstall-release")
	scripts := filepath.Join(base, "scripts")
	if e = os.Mkdir(scripts, 0700); e != nil {
		t.Fatal(e)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	script := "#!/bin/sh\nset -eu\n: > " + quote(enter) + "\n" +
		"i=0\nwhile [ \"$i\" -lt 25 ]; do\n" +
		"  [ ! -f " + quote(release) + " ] || exit 0\n" +
		"  /bin/sleep 1\n  i=$((i+1))\ndone\nexit 1\n"
	if e = os.WriteFile(filepath.Join(scripts, "postinstall"), []byte(script), 0755); e != nil {
		t.Fatal(e)
	}
	paused := filepath.Join(base, "paused-subject.pkg")
	run("/usr/bin/pkgbuild", "--root", filepath.Join(base, "subject-source"), "--scripts", scripts,
		"--identifier", id, "--version", version, "--install-location", dest, paused)
	exerciseNativeReceiptForgetWindow(t, command, paused, enter, release, id, root)
	assertPayload(dest)
	if pairHash(controlID) != controlHash {
		t.Fatal("contended reinstall changed the control receipt")
	}
	// Restore and verify the subject independently of when Installer chose
	// to write its receipt relative to postinstall.
	run("/usr/sbin/installer", "-pkg", subject, "-target", "/")
	checkReceipt(id, dest)
	assertPayload(dest)
	assertPayload(controlDest)
}

func exerciseNativeReceiptForgetWindow(t *testing.T, command func(context.Context, string, ...string) *exec.Cmd, pkg, enter, release, id string, receipts *os.File) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := command(ctx, "/usr/sbin/installer", "-pkg", pkg, "-target", "/")
	if e := cmd.Start(); e != nil {
		t.Fatal("could not launch Installer contention fixture", e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	reaped := false
	defer func() {
		if e := os.WriteFile(release, nil, 0600); e != nil {
			t.Error("could not release Installer fixture", e)
		}
		if !reaped {
			if e := <-done; e != nil {
				t.Error("could not finish Installer fixture", e)
			}
		}
	}()
	checkEntered := func() bool {
		info, e := os.Lstat(enter)
		if errors.Is(e, os.ErrNotExist) {
			return false
		}
		if e != nil || !info.Mode().IsRegular() || info.Size() != 0 {
			t.Fatal("unexpected Installer postinstall marker", e)
		}
		return true
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for !checkEntered() {
		select {
		case e := <-done:
			reaped = true
			t.Fatal("Installer exited before entering postinstall", e)
		case <-deadline.C:
			t.Fatal("Installer did not reach postinstall by the deadline")
		case <-tick.C:
		}
	}
	// Verify the subject preimage while the Installer script is still held.
	readPair := func() [2]bool {
		t.Helper()
		var present [2]bool
		for i, ext := range []string{".bom", ".plist"} {
			raw, _, e := readAt(receipts, id+ext, 4<<20)
			if darwintrust.IsReadAbsent(e) {
				continue
			}
			if e != nil || len(raw) == 0 {
				t.Fatal("could not inspect the subject receipt pair", e)
			}
			present[i] = true
		}
		return present
	}
	requireRunning := func() {
		select {
		case e := <-done:
			reaped = true
			t.Fatal("Installer exited before contention was observed", e)
		default:
		}
	}
	requireRunning()
	// Installer can temporarily remove its prior receipt itself. This is
	// an inconclusive probe, since there is no complete pair to contend for.
	before := readPair()
	requireRunning()
	if before != ([2]bool{true, true}) {
		fmt.Println("::notice title=macOS receipt contention::subject-pair-unavailable-during-postinstall")
		return
	}
	forgetErr := forgetRemovalReceipt(ctx, id)
	present := readPair()
	requireRunning()
	switch {
	case forgetErr == nil && present == ([2]bool{}):
		fmt.Println("::notice title=macOS receipt contention::receipt-forgotten-during-postinstall")
	case forgetErr != nil && present == ([2]bool{true, true}):
		fmt.Println("::notice title=macOS receipt contention::receipt-unchanged-after-forget-error")
	default:
		t.Fatal("pkgutil result and subject receipt state disagree during postinstall")
	}
}

func TestDarwinRemovalReceiptRecovery(t *testing.T) {
	requireHostedReceiptFixture(t)
	capsule, e := os.MkdirTemp("/private/tmp", "accessweaver-deployment-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(capsule); e != nil {
			t.Error(e)
		}
	})
	fixtures := filepath.Join(capsule, "schema2-bridge")
	if e = os.Mkdir(fixtures, 0755); e != nil {
		t.Fatal(e)
	}
	for _, scenario := range []string{"partial-forget", "after-forget", "missing", "extra", "replaced"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			f := newOwnedRemovalTargetFixture(t, fixtures, true, true)
			if e := os.Chmod(f.base, 0755); e != nil {
				t.Fatal(e)
			}
			if e := f.intent.quarantinePublicAppUsing(ctx, f.resolve); e != nil {
				t.Fatal(e)
			}
			completeOwnedRemovalObjects(t, f)
			completeOwnedQuarantinedApp(t, f)
			calls := 0
			forget := func(context.Context, string) error {
				calls++
				return errors.New("tool must not run yet")
			}
			if _, e := f.intent.retireNextReceiptUsing(ctx, f.resolve, forget); e == nil || calls != 0 {
				t.Fatal("receipt operation ran before registration retirement", e)
			}
			if _, e := f.intent.removeNextRegistrationUsing(ctx, f.resolve); e != nil {
				t.Fatal(e)
			}
			actions, e := removalAllActions(f.intent.plan)
			if e != nil || len(actions) != 13 {
				t.Fatal("unexpected fixture action sequence", e)
			}
			if record, e := f.intent.verifyCompletedRemoval(ctx, f.resolve); e == nil || record != nil {
				t.Fatal("incomplete removal returned a handoff record", e)
			}
			if published, e := f.intent.finalizeRemovalUsing(ctx, f.resolve); e == nil || published {
				t.Fatal("incomplete removal published a replacement authority", published, e)
			}
			id, _, e := receiptActionPair(f.intent.plan, actions[10])
			if e != nil {
				t.Fatal(e)
			}
			bom := filepath.Join(f.receiptRoot, id+".bom")
			plist := filepath.Join(f.receiptRoot, id+".plist")
			switch scenario {
			case "missing":
				if e = os.Remove(bom); e != nil {
					t.Fatal(e)
				}
			case "extra":
				if e = os.WriteFile(filepath.Join(f.receiptRoot, BundleID+".unknown.plist"), []byte("unknown owned fixture"), 0644); e != nil {
					t.Fatal(e)
				}
			case "replaced":
				if e = os.WriteFile(plist, []byte("independent change"), 0644); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "missing" || scenario == "extra" || scenario == "replaced" {
				before := ownedRemovalTargetSnapshot(t, f.base)
				if _, e = f.intent.retireNextReceiptUsing(ctx, f.resolve, forget); e == nil || calls != 0 {
					t.Fatal("invalid receipt reached tool invocation", e)
				}
				if !bytes.Equal(before, ownedRemovalTargetSnapshot(t, f.base)) {
					t.Fatal("receipt refusal changed owned state")
				}
				return
			}

			forget = func(_ context.Context, got string) error {
				if got != id {
					t.Fatal("tool received a different receipt ID", got)
				}
				calls++
				if e := os.Remove(bom); e != nil {
					t.Fatal(e)
				}
				if scenario == "partial-forget" {
					return errors.New("interrupted while forgetting pair")
				}
				return os.Remove(plist)
			}
			if scenario == "after-forget" {
				f.store.observe = func(phase string) error {
					if phase == "removal-receipt-forgotten" {
						return errors.New("interrupted before receipt completion")
					}
					return nil
				}
			}
			if _, e = f.intent.retireNextReceiptUsing(ctx, f.resolve, forget); e == nil || calls != 1 {
				t.Fatal("receipt interruption not observed", e)
			}
			reopenOwnedRemovalFileIntent(t, f)
			forget = func(_ context.Context, got string) error {
				if got != id || scenario != "partial-forget" {
					t.Fatal("unexpected receipt tool retry", got)
				}
				calls++
				return os.Remove(plist)
			}
			got, e := f.intent.retireNextReceiptUsing(ctx, f.resolve, forget)
			if e != nil || got != (removalProgress{11, 13}) {
				t.Fatal("pending receipt did not complete", got, e)
			}
			wantCalls := 1
			if scenario == "partial-forget" {
				wantCalls++
			}
			if calls != wantCalls {
				t.Fatal("receipt tool call count differs", calls)
			}
			forget = func(_ context.Context, got string) error {
				return errors.Join(os.Remove(filepath.Join(f.receiptRoot, got+".bom")), os.Remove(filepath.Join(f.receiptRoot, got+".plist")))
			}
			for completed := 12; completed <= len(actions); completed++ {
				got, e = f.intent.retireNextReceiptUsing(ctx, f.resolve, forget)
				if e != nil || got != (removalProgress{completed, len(actions)}) {
					t.Fatal("receipt sequence did not advance", got, e)
				}
			}
			reopenOwnedRemovalFileIntent(t, f)
			verifyRetry := func() (removalProgress, error) {
				return f.intent.retireNextReceiptUsing(ctx, f.resolve, func(context.Context, string) error {
					t.Fatal("completed receipt sequence called the tool again")
					return nil
				})
			}
			syncFailure := errors.New("interrupted while syncing completed removal progress")
			f.store.observe = func(phase string) error {
				if phase == "removal-journal-before-file-sync" {
					return syncFailure
				}
				return nil
			}
			if got, e = verifyRetry(); !errors.Is(e, syncFailure) || got != (removalProgress{}) {
				t.Fatal("acknowledged removal after a failed journal sync", got, e)
			}
			reopenOwnedRemovalFileIntent(t, f)
			// Recreate an owned receipt during synchronization. Terminal
			// verification must reject it without running the tool again.
			f.store.observe = func(phase string) error {
				if phase == "removal-journal-before-directory-sync" {
					return os.WriteFile(bom, []byte("another receipt"), 0644)
				}
				return nil
			}
			if got, e = verifyRetry(); e == nil || got != (removalProgress{}) {
				t.Fatal("acknowledged removal with a reappeared receipt", got, e)
			}
			if e = os.Remove(bom); e != nil {
				t.Fatal(e)
			}
			reopenOwnedRemovalFileIntent(t, f)
			got, e = verifyRetry()
			if e != nil || got != (removalProgress{len(actions), len(actions)}) {
				t.Fatal("receipt completion is not idempotent", got, e)
			}
			record, e := f.intent.verifyCompletedRemoval(ctx, f.resolve)
			if e != nil || !bytes.Equal(record, f.store.encoded) {
				t.Fatal("completion did not return the exact deployment record", e)
			}
			state, e := decodeDeployment(record)
			identity := f.intent.fence.Target.Identity
			if e != nil || state.Generation != f.intent.fence.BaseGeneration+1 || state.HighWaterVersion != identity.Version ||
				state.Active != (deploymentSlot{}) || len(state.Pending) != 0 {
				t.Fatal("completion lost the inactive generation or downgrade guard", e)
			}
			if e = state.canPrepare(identity); e != nil {
				t.Fatal("preserved record refused the same release", e)
			}
			identity.Version = "0.1.0"
			if e = state.canPrepare(identity); e == nil {
				t.Fatal("preserved record admitted an older release")
			}
			entries, e := os.ReadDir(f.receiptRoot)
			if e != nil || len(entries) != 1 || entries[0].Name() != "unrelated-private.plist" {
				t.Fatal("receipt retirement changed unrelated inventory", e)
			}
			if e = os.Chmod(f.base, 0700); e != nil {
				t.Fatal(e)
			}
			exerciseOwnedRemovalHandoff(t, f, record, scenario == "after-forget")
		})
	}
}

func exerciseOwnedRemovalHandoff(t *testing.T, f *ownedRemovalTargetFixture, record []byte, interruptAfterExchange bool) {
	t.Helper()
	ctx := context.Background()
	archive := filepath.Join(f.base, removalArchiveName(f.intent.fence))
	root := filepath.Join(f.base, deploymentRoot)
	previous, e := os.Stat(root)
	if e != nil {
		t.Fatal(e)
	}
	oldState := filepath.Join(root, "state")
	oldJournal, e := os.ReadFile(filepath.Join(oldState, removalJournalName))
	if e != nil {
		t.Fatal(e)
	}
	oldPlan, e := os.ReadFile(filepath.Join(oldState, removalPlanName))
	if e != nil {
		t.Fatal(e)
	}
	if interruptAfterExchange {
		killOwnedRemovalHandoff(t, f, "removal-handoff-exchanged")
		verifyOwnedRemovalHandoff(t, f, previous, record, oldJournal, oldPlan)
		return
	}
	phase := "removal-handoff-reserved"
	interrupted := errors.New("interrupted authority handoff")
	f.store.observe = func(p string) error {
		if p == phase {
			return interrupted
		}
		return nil
	}
	published, e := f.intent.finalizeRemovalUsing(ctx, f.resolve)
	if !errors.Is(e, interrupted) || published {
		t.Fatal("unexpected handoff publication boundary", published, e)
	}
	{
		staged, e := os.Stat(archive)
		if e != nil || os.SameFile(previous, staged) {
			t.Fatal("clean staged authority was not reserved", e)
		}
		reopenOwnedRemovalFileIntent(t, f)
		reservedRecord := filepath.Join(archive, "state", deploymentRecord)
		if e = os.WriteFile(reservedRecord, []byte("changed reserved record"), 0644); e != nil {
			t.Fatal(e)
		}
		if published, e = f.intent.finalizeRemovalUsing(ctx, f.resolve); e == nil || published {
			t.Fatal("handoff accepted a changed reserved record", published, e)
		}
		if current, e := os.Stat(root); e != nil || !os.SameFile(current, previous) {
			t.Fatal("refused handoff displaced the original authority", e)
		}
		if e = os.WriteFile(reservedRecord, record, 0644); e != nil {
			t.Fatal(e)
		}
		killOwnedRemovalHandoff(t, f, phase)
		reopenOwnedRemovalFileIntent(t, f)
		if published, e = f.intent.finalizeRemovalUsing(ctx, f.resolve); e != nil || !published {
			t.Fatal("handoff retry did not publish", published, e)
		}
		current, e := os.Stat(root)
		if e != nil || !os.SameFile(current, staged) {
			t.Fatal("handoff retry did not reuse the staged authority", e)
		}
	}
	verifyOwnedRemovalHandoff(t, f, previous, record, oldJournal, oldPlan)
}

func requireOwnedRemovalHandoffLeases(t *testing.T, base string) {
	t.Helper()
	root, e := os.Open(filepath.Join(base, deploymentRoot))
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	lock, e := darwintrust.OpenRegularAt(root, deploymentLock, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(e, unix.EWOULDBLOCK) {
		t.Fatal("canonical writer lease was not held during handoff", e)
	}
	lease, e := runtimeFileAt(root, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	if e = unix.Flock(int(lease.Fd()), unix.LOCK_SH|unix.LOCK_NB); !errors.Is(e, unix.EWOULDBLOCK) {
		t.Fatal("canonical runtime lease was not held during handoff", e)
	}
}

func killOwnedRemovalHandoff(t *testing.T, f *ownedRemovalTargetFixture, phase string) {
	t.Helper()
	if e := f.intent.Close(); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestDarwinRemovalFileKilledChild$", "-test.v", "-test.timeout=32s")
	command.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "TZ=UTC",
		"GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "RUNNER_OS=macOS",
		"ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST=1",
		removalKillBaseEnv + "=" + f.base, removalKillPhaseEnv + "=" + phase,
	}
	output := &ownedRemovalKillOutput{}
	command.Stdout, command.Stderr = output, output
	e = command.Run()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(e, &exit) {
		t.Fatal("handoff child did not terminate at the boundary", e)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL ||
		bytes.Count(output.data, []byte("OWNED-REMOVAL-SIGKILL "+phase+"\n")) != 1 {
		t.Fatal("handoff child signal or boundary marker differs")
	}
}

func verifyOwnedRemovalHandoff(t *testing.T, f *ownedRemovalTargetFixture, previous os.FileInfo, record, oldJournal, oldPlan []byte) {
	t.Helper()
	if e := f.intent.Close(); e != nil {
		t.Fatal(e)
	}
	identity := f.intent.fence.Target.Identity
	archive := filepath.Join(f.base, removalArchiveName(f.intent.fence))
	root := filepath.Join(f.base, deploymentRoot)
	archived, e := os.Stat(archive)
	if e != nil || !os.SameFile(previous, archived) {
		t.Fatal("handoff did not archive the original authority", e)
	}
	assertRemovalArchiveFile := func(file string, expected []byte) {
		t.Helper()
		actual, e := os.ReadFile(filepath.Join(archive, "state", file))
		if e != nil || !bytes.Equal(actual, expected) {
			t.Fatal("archived removal evidence changed", file, e)
		}
	}
	parent, e := os.Open(f.base)
	if e != nil {
		t.Fatal(e)
	}
	if old, e := openRemovalIntentAt(parent, 0, identity, f.intent.fence.DesktopRecordSHA256); e == nil {
		old.Close()
		t.Fatal("archived removal intent still opens through the canonical path")
	}
	parent, e = os.Open(f.base)
	if e != nil {
		t.Fatal(e)
	}
	s, e := beginDeploymentMode(parent, 0, nil, false)
	if e != nil {
		t.Fatal("ordinary deployment writer did not reopen after handoff", e)
	}
	defer s.Close()
	if !bytes.Equal(s.encoded, record) {
		t.Fatal("ordinary deployment writer did not reopen the preserved record")
	}
	older := identity
	older.Version = "0.1.0"
	if _, e = s.prepare(older); e == nil {
		t.Fatal("reopened authority admitted a downgrade")
	}
	if entries, e := os.ReadDir(filepath.Join(root, "versions")); e != nil || len(entries) != 0 {
		t.Fatal("refused downgrade changed the clean versions directory", e)
	}
	slot, e := s.prepare(identity)
	if e != nil || len(s.state.Pending) != 1 || s.state.Pending[0].Slot != slot {
		t.Fatal("ordinary deployment writer could not prepare the same version", e)
	}
	assertRemovalArchiveFile(deploymentRecord, record)
	assertRemovalArchiveFile(removalJournalName, oldJournal)
	assertRemovalArchiveFile(removalPlanName, oldPlan)
}
