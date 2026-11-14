//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
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
// VM. The package installs a text file under the fixture root and has no scripts.
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
	run := func(path string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if e := cmd.Run(); e != nil {
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
}

func TestDarwinRemovalReceiptRecovery(t *testing.T) {
	requireHostedReceiptFixture(t)
	for _, scenario := range []string{"partial-forget", "after-forget", "missing", "extra", "replaced"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			f := newOwnedRemovalTargetFixture(t, t.TempDir(), true, true)
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
			got, e = f.intent.retireNextReceiptUsing(ctx, f.resolve, func(context.Context, string) error {
				t.Fatal("completed receipt sequence called the tool again")
				return nil
			})
			if e != nil || got != (removalProgress{len(actions), len(actions)}) {
				t.Fatal("receipt completion is not idempotent", got, e)
			}
			entries, e := os.ReadDir(f.receiptRoot)
			if e != nil || len(entries) != 1 || entries[0].Name() != "unrelated-private.plist" {
				t.Fatal("receipt retirement changed unrelated inventory", e)
			}
		})
	}
}
