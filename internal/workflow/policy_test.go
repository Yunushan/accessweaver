package workflow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
)

func workflowPolicy(t *testing.T, p managed.Policy) *managed.Authority {
	t.Helper()
	now := time.Now().UTC()
	p.SchemaVersion = 1
	p.Revision = 1
	p.IssuedAt = now.Add(-time.Minute)
	p.ExpiresAt = now.Add(time.Hour)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := private.Public().(ed25519.PublicKey)
	envelope, err := managed.Sign(data, private, now)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := managed.PrepareInstallation(envelope, public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := managed.DecodeInstallation(installation, now)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func TestWorkflowPolicyRevocationPrecedesJobCreation(t *testing.T) {
	request := Request{Action: "dns", DNS: "doh"}
	digest, err := request.PolicyDigest()
	if err != nil {
		t.Fatal(err)
	}
	allowed := workflowPolicy(t, managed.Policy{Workflows: []managed.WorkflowRule{{Action: request.Action, InputSHA256: digest}}})
	denied := workflowPolicy(t, managed.Policy{})
	revoked := false
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		if revoked {
			return denied, nil
		}
		return allowed, nil
	})
	root := t.TempDir()
	manager := NewWithGuard(root, guard)
	manager.platform = "windows"
	manager.requireAdmin = func() error { return nil }
	manager.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		t.Error("revoked workflow reached worker")
		return nil, nil
	}
	plan, err := manager.Preview(request)
	if err != nil || !plan.Ready {
		t.Fatal("approved request unavailable", err, plan.Issues)
	}
	revoked = true
	if _, err := manager.Start(plan.ID); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("revoked workflow started", err)
	}
	if _, err := os.Stat(filepath.Join(root, "workflows")); !os.IsNotExist(err) {
		t.Fatal("revoked workflow created a job directory", err)
	}
}

func TestDownloadPermissionBlocksApprovedRemoteChecks(t *testing.T) {
	request := Request{Action: "updates"}
	digest, err := request.PolicyDigest()
	if err != nil {
		t.Fatal(err)
	}
	authority := workflowPolicy(t, managed.Policy{Workflows: []managed.WorkflowRule{{Action: request.Action, InputSHA256: digest}}})
	guard := managed.NewGuard(func() (*managed.Authority, error) { return authority, nil })
	if _, err := workflowPermission(guard, request); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("release check bypassed download restriction", err)
	}
}

func TestWorkflowShutdownRemainsResponsiveDuringPolicyCheck(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	reads := 0
	guard := managed.NewGuard(func() (*managed.Authority, error) {
		reads++
		if reads == 2 {
			close(entered)
			<-release
		}
		return nil, nil
	})
	root := t.TempDir()
	manager := NewWithGuard(root, guard)
	manager.platform = "windows"
	plan, err := manager.Preview(Request{Action: "discover"})
	if err != nil || !plan.Ready {
		t.Fatal(err, plan.Issues)
	}
	started := make(chan error, 1)
	go func() { _, err := manager.Start(plan.ID); started <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("start did not reach policy check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Shutdown(ctx); err != nil {
		close(release)
		t.Fatal("policy I/O blocked shutdown", err)
	}
	close(release)
	select {
	case err := <-started:
		if err == nil {
			t.Fatal("shutdown allowed a late workflow")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start did not finish")
	}
	if _, err := os.Stat(filepath.Join(root, "workflows")); !os.IsNotExist(err) {
		t.Fatal("shutdown allowed late job storage", err)
	}
}
