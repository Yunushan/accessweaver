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

func TestDesktopAccessIsCheckedBeforeJobStorage(t *testing.T) {
	requests := []Request{
		{Action: "app-install", Engine: "discord"},
		{Action: "app-remove", Engine: "discord-ptb"},
		{Action: "app-reinstall", Engine: "discord"},
		{Action: "app-start", Engine: "splitcord"},
	}
	for _, request := range requests {
		t.Run(request.Action+"/"+request.Engine, func(t *testing.T) {
			m := New(t.TempDir())
			m.platform = "windows"
			refused := errors.New("fixture: unusable desktop token")
			m.requireDesktop = func() error { return refused }
			m.requireAdmin = func() error {
				t.Error("desktop workflow checked administrator access")
				return refused
			}
			m.openStoreLease = func(string) (workflowStoreLease, error) {
				t.Error("desktop refusal reserved workflow storage")
				return nil, refused
			}
			m.execute = func(context.Context, string, Request) (json.RawMessage, error) {
				t.Error("desktop refusal started the worker")
				return nil, refused
			}
			blocked, err := m.Preview(request)
			if err != nil || blocked.Ready || blocked.RequiresAdministrator || len(blocked.Issues) != 1 || blocked.Issues[0] != refused.Error() {
				t.Fatalf("desktop preview: %+v, %v", blocked, err)
			}
			if _, err = m.Start(blocked.ID); err == nil || err.Error() != refused.Error() {
				t.Fatalf("blocked workflow start: %v", err)
			}

			m.requireDesktop = func() error { return nil }
			ready, err := m.Preview(request)
			if err != nil || !ready.Ready || ready.RequiresAdministrator {
				t.Fatalf("interactive desktop preview: %+v, %v", ready, err)
			}
			m.requireDesktop = func() error { return refused }
			if _, err = m.Start(ready.ID); !errors.Is(err, refused) {
				t.Fatalf("desktop access was not rechecked: %v", err)
			}
			if m.Snapshot().ID != "" {
				t.Fatal("desktop refusal admitted a workflow job")
			}
			if _, err = os.Stat(m.root); !os.IsNotExist(err) {
				t.Fatalf("desktop refusal created workflow state: %v", err)
			}
		})
	}
}

func TestReadAndUserOperationsDoNotRequireAdministrator(t *testing.T) {
	m := New(t.TempDir())
	m.platform = "windows"
	m.requireAdmin = func() error { t.Error("read/user operation required admin"); return errors.New("unexpected check") }
	m.requireDesktop = func() error { return nil }
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
