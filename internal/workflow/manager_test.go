package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPlanValidationAndUnsupportedHost(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "linux"
	p, e := m.Preview(Request{Action: "install", Engine: "byedpi"})
	if e != nil || p.Ready || len(p.Issues) == 0 {
		t.Fatalf("unsupported host: %+v %v", p, e)
	}
	if _, e = m.Start(p.ID); e == nil {
		t.Fatal("unsupported plan started")
	}
	for _, r := range []Request{{Action: "invented"}, {Action: "config", Applications: []string{"app.exe,other.exe"}}, {Action: "hostlist", Engine: "zapret2", Domains: []string{"https://example.com"}}, {Action: "scan", Scan: "invalid"}, {Action: "config", ProfileID: "../escape"}, {Action: "install", Args: []string{"bad\x00value"}}} {
		if _, e = m.Preview(r); e == nil {
			t.Fatalf("invalid request accepted: %+v", r)
		}
	}
}

func TestOperationComponentCompatibility(t *testing.T) {
	for _, request := range []Request{
		{Action: "install", Engine: "discord"}, {Action: "remove", Engine: "wgcf"},
		{Action: "hostlist", Engine: "wiresock"}, {Action: "app-install", Engine: "byedpi"},
		{Action: "app-repair", Engine: "discord-ptb"}, {Action: "install", Engine: "byedpi", Mode: "alternative"},
	} {
		if err := request.Validate(); err == nil {
			t.Fatalf("unsupported combination accepted: %+v", request)
		}
	}
	for _, request := range []Request{{Action: "install", Engine: "byedpi", Mode: "dll"}, {Action: "app-repair", Engine: "discord"}, {Action: "remove", Engine: "windivert"}} {
		if err := request.Validate(); err != nil {
			t.Fatalf("supported combination rejected: %+v: %v", request, err)
		}
	}
}

func TestApplicationPrivilegeReview(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { return nil }
	p, err := m.Preview(Request{Action: "app-repair", Engine: "discord"})
	if err != nil || p.Ready || len(p.Issues) == 0 {
		t.Fatalf("combined repair must be blocked: %+v %v", p, err)
	}
	if _, err = m.Start(p.ID); err == nil {
		t.Fatal("combined repair started without a privilege-separated broker")
	}
	for _, action := range []string{"app-install", "app-remove", "app-start"} {
		if _, err = m.Preview(Request{Action: action, Engine: "discord", DNS: "doh"}); err == nil {
			t.Fatalf("%s accepted machine DNS mutation", action)
		}
		p, err = m.Preview(Request{Action: action, Engine: "discord", DNS: "unchanged"})
		if err != nil || !p.Ready {
			t.Fatalf("user application operation: %+v %v", p, err)
		}
	}
}

func TestAccountConsentAndModeSpecificReview(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { return nil }
	account, err := m.Preview(Request{Action: "config"})
	if err != nil || account.Ready {
		t.Fatalf("new account without consent: %+v %v", account, err)
	}
	existing, err := m.Preview(Request{Action: "config", ConfigPath: "existing.conf"})
	if err != nil || !existing.Ready {
		t.Fatalf("existing config: %+v %v", existing, err)
	}
	proxy, err := m.Preview(Request{Action: "install", Engine: "byedpi", Mode: "once"})
	if err != nil || !proxy.Ready {
		t.Fatal(proxy, err)
	}
	for _, step := range proxy.Steps {
		if strings.Contains(step, "service") || strings.Contains(step, "wgcf") {
			t.Fatalf("one-shot review claimed unrelated change: %s", step)
		}
	}
	for _, warning := range proxy.Warnings {
		if strings.Contains(warning, "Cloudflare") {
			t.Fatal("proxy-only plan asks about WARP")
		}
	}
}

func TestPlansAreImmutableExpiringAndSingleUse(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { return nil }
	input := Request{Action: "config", ConfigPath: "fixture.conf", Applications: []string{"original.exe"}}
	p, e := m.Preview(input)
	if e != nil {
		t.Fatal(e)
	}
	input.Applications[0] = "mutated.exe"
	p.Request.Applications[0] = "also-mutated.exe"
	m.execute = func(ctx context.Context, dir string, r Request) (json.RawMessage, error) {
		if r.Applications[0] != "original.exe" {
			return nil, errors.New("reviewed request changed")
		}
		return json.RawMessage(`{"ok":true}`), nil
	}
	if _, e = m.Start(p.ID); e != nil {
		t.Fatal(e)
	}
	waitJob(t, m)
	if m.Snapshot().State != "succeeded" {
		t.Fatal(m.Snapshot())
	}
	if _, e = m.Start(p.ID); e == nil {
		t.Fatal("consumed plan reused")
	}
	p, _ = m.Preview(Request{Action: "discover"})
	m.mu.Lock()
	stored := m.plans[p.ID]
	stored.ExpiresAt = time.Now().Add(-time.Second)
	m.plans[p.ID] = stored
	m.mu.Unlock()
	if _, e = m.Start(p.ID); e == nil {
		t.Fatal("expired plan started")
	}
	history, e := m.History()
	if e != nil || len(history) != 1 || history[0].State != "succeeded" {
		t.Fatalf("history: %+v %v", history, e)
	}
}

func TestConcurrentJobAndCancellationPersistFailure(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { return nil }
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	p, _ := m.Preview(Request{Action: "discover"})
	if _, e := m.Start(p.ID); e != nil {
		t.Fatal(e)
	}
	p2, _ := m.Preview(Request{Action: "discover"})
	if _, e := m.Start(p2.ID); e == nil {
		t.Fatal("two system jobs started")
	}
	m.Cancel()
	waitJob(t, m)
	if j := m.Snapshot(); j.State != "failed" || !strings.Contains(j.Error, "canceled") {
		t.Fatalf("cancellation outcome: %+v", j)
	}
	history, e := m.History()
	if e != nil || len(history) != 1 || history[0].State != "failed" {
		t.Fatalf("failed history: %+v %v", history, e)
	}
}
func waitJob(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.Snapshot().State != "running" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("job did not complete")
}

func TestShutdownWaitsForDurableOutcomeAndRejectsNewJobs(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { return nil }
	executing := make(chan struct{})
	finishing := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	m.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
		close(executing)
		<-ctx.Done()
		close(finishing)
		<-release
		return nil, ctx.Err()
	}
	p, err := m.Preview(Request{Action: "discover"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Start(p.ID); err != nil {
		t.Fatal(err)
	}
	// This case exercises cleanup after execution has actually begun.
	select {
	case <-executing:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not enter execution")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err = m.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("premature shutdown: %v", err)
	}
	<-finishing
	p, err = m.Preview(Request{Action: "discover"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Start(p.ID); err == nil {
		t.Fatal("job accepted after shutdown began")
	}
	close(release)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err = m.Shutdown(ctx2); err != nil {
		t.Fatal(err)
	}
	history, err := m.History()
	if err != nil || len(history) != 1 || history[0].State != "failed" || history[0].FinishedAt.IsZero() {
		t.Fatalf("outcome not durable: %+v %v", history, err)
	}
}

func TestByeDPIInstallRejectsReservedOptionsBeforeRetainingPlan(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { return nil }
	for _, arg := range []string{"--i=0.0.0.0", "--po=9999", "--dae", "--service", "--trans", "-Ui0.0.0.0", "--", "@options.txt"} {
		if _, err := m.Preview(Request{Action: "install", Engine: "byedpi", Mode: "service", Args: []string{arg}}); err == nil {
			t.Errorf("unsafe preview accepted: %q", arg)
		}
	}
	if len(m.plans) != 0 {
		t.Fatal("invalid request retained as reviewed plan")
	}
	if p, err := m.Preview(Request{Action: "install", Engine: "byedpi", Mode: "service", Args: []string{"--split", "2"}}); err != nil || !p.Ready {
		t.Fatalf("normal strategy: %+v %v", p, err)
	}
}
