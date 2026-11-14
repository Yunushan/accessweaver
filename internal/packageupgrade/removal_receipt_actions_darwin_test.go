//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinRemovalReceiptRecovery(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_TEST") != "1" {
		t.Skip("requires opted-in hosted macOS runner")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("receipt removal test requires a disposable hosted Mac")
	}
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
