package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestMachinePreviewExplainsMissingAuthorityWithoutExecution(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	denied := errors.New("fixture: separately elevated CLI required")
	m.requireAdmin = func() error { return denied }
	m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
		t.Error("unprivileged machine plan executed")
		return nil, nil
	}
	p, err := m.Preview(Request{Action: "install", Engine: "byedpi", Mode: "service"})
	if err != nil || p.Ready || !p.RequiresAdministrator || len(p.Issues) != 1 || p.Issues[0] != denied.Error() {
		t.Fatalf("authority review: %+v %v", p, err)
	}
	if _, err = m.Start(p.ID); err == nil {
		t.Fatal("unprivileged plan started")
	}
	if _, err = os.Stat(m.root); !os.IsNotExist(err) {
		t.Fatalf("blocked plan created workflow state: %v", err)
	}
	p.Request.Args = []string{"edited after review"}
	if len(m.plans[p.ID].Request.Args) != 0 {
		t.Fatal("reviewed export request aliases stored plan")
	}
}

func TestMachineAuthorityIsRecheckedBeforeJobStarts(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { return nil }
	p, err := m.Preview(Request{Action: "dns", DNS: "doh"})
	if err != nil || !p.Ready {
		t.Fatalf("admin review: %+v %v", p, err)
	}
	denied := errors.New("fixture authority no longer available")
	m.requireAdmin = func() error { return denied }
	if _, err = m.Start(p.ID); !errors.Is(err, denied) {
		t.Fatalf("authority recheck missing: %v", err)
	}
	if _, err = os.Stat(m.root); !os.IsNotExist(err) {
		t.Fatalf("authority loss created workflow state: %v", err)
	}
}

func TestReadAndUserOperationsDoNotRequireAdministrator(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { t.Error("read/user operation required admin"); return errors.New("unexpected check") }
	for _, r := range []Request{{Action: "discover"}, {Action: "updates"}, {Action: "choose-folder"}, {Action: "app-install", Engine: "discord"}, {Action: "app-start", Engine: "discord"}, {Action: "app-remove", Engine: "discord"}} {
		p, err := m.Preview(r)
		if err != nil || !p.Ready || p.RequiresAdministrator {
			t.Fatalf("user review: %+v %v", p, err)
		}
	}
	if !requiresAdministrator("future-machine-operation") {
		t.Fatal("unknown operation defaults to unrestricted authority")
	}
}
