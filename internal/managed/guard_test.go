package managed

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func guardAuthority(t *testing.T, p Policy) *Authority {
	t.Helper()
	_, public, private, now := fixture(t)
	p.SchemaVersion = 1
	p.Revision = 2
	p.IssuedAt = now.Add(-1e9)
	p.ExpiresAt = now.Add(1e12)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(data, private, now)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := PrepareInstallation(signed, public, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := DecodeInstallation(installed, now)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}
func TestGuardDefaultDenialAndSourceFailure(t *testing.T) {
	authority := guardAuthority(t, Policy{})
	for name, source := range map[string]func() (*Authority, error){"deny": func() (*Authority, error) { return authority, nil }, "source failure": func() (*Authority, error) { return nil, ErrUnavailable }} {
		t.Run(name, func(t *testing.T) {
			g := NewGuard(source)
			checks := []error{g.ProfileChanges(), g.Diagnostics(), g.Launch(LaunchRequest{}), g.ServiceHost()}
			_, err := g.Workflow("dns", strings.Repeat("a", 64), nil)
			checks = append(checks, err)
			for _, err := range checks {
				if !IsPolicyError(err) {
					t.Fatal("managed action failed open", err)
				}
			}
		})
	}
	unmanaged := NewGuard(func() (*Authority, error) { return nil, nil })
	if unmanaged.ProfileChanges() != nil || unmanaged.Diagnostics() != nil || unmanaged.Launch(LaunchRequest{}) != nil || unmanaged.ServiceHost() != nil {
		t.Fatal("unmanaged behavior changed")
	}
}
func TestLaunchApprovalBindsFilesAndRejectsUnsupportedInputs(t *testing.T) {
	hash := strings.Repeat("a", 64)
	configHash := strings.Repeat("b", 64)
	authority := guardAuthority(t, Policy{Launches: []LaunchRule{{Engine: "byedpi", InputSHA256: hash, BinarySHA256: hash, ConfigSHA256: configHash}}})
	g := NewGuard(func() (*Authority, error) { return authority, nil })
	calls := 0
	g.protect = func(path, digest string, directory bool) error {
		calls++
		if directory {
			t.Fatal("file treated as directory")
		}
		if path == "approved.exe" && digest == hash || path == "approved.conf" && digest == configHash {
			return nil
		}
		return errors.New("unapproved bytes")
	}
	input := LaunchRequest{Engine: "byedpi", InputSHA256: hash, Binary: "approved.exe", ConfigPath: "approved.conf"}
	if err := g.Launch(input); err != nil || calls != 2 {
		t.Fatal("approved immutable inputs rejected", err, calls)
	}
	input.Binary = "replaced.exe"
	if err := g.Launch(input); !errors.Is(err, ErrDenied) {
		t.Fatal("changed binary accepted", err)
	}
	input.Binary = "approved.exe"
	input.ConfigPath = "replaced.conf"
	if err := g.Launch(input); !errors.Is(err, ErrDenied) {
		t.Fatal("changed config accepted", err)
	}
	input.ConfigPath = "approved.conf"
	input.GeneratedInputs = true
	if err := g.Launch(input); !errors.Is(err, ErrDenied) {
		t.Fatal("user generated inputs accepted", err)
	}
	input.GeneratedInputs = false
	input.RawArguments = true
	if err := g.Launch(input); !errors.Is(err, ErrDenied) {
		t.Fatal("unvalidated native argument assets accepted", err)
	}
	input.RawArguments = false
	input.InputSHA256 = configHash
	if err := g.Launch(input); !errors.Is(err, ErrDenied) {
		t.Fatal("different launch inputs accepted", err)
	}
}
func TestWorkflowApprovalAndDownloadPermission(t *testing.T) {
	hash := strings.Repeat("a", 64)
	authority := guardAuthority(t, Policy{AllowProfileChanges: true, AllowDiagnostics: true, Workflows: []WorkflowRule{{Action: "dns", InputSHA256: hash}}})
	g := NewGuard(func() (*Authority, error) { return authority, nil })
	if g.ProfileChanges() != nil || g.Diagnostics() != nil {
		t.Fatal("explicit permission ignored")
	}
	result, err := g.Workflow("dns", hash, nil)
	if err != nil || !result.Managed || result.AllowDownloads {
		t.Fatal("download restriction lost", err, result)
	}
	if _, err := g.Workflow("remove-all", hash, nil); !errors.Is(err, ErrDenied) {
		t.Fatal("wrong action approved", err)
	}
	g.protect = func(string, string, bool) error { return errors.New("mutable input") }
	if _, err := g.Workflow("dns", hash, []InputPath{{Path: "user-config"}}); !errors.Is(err, ErrDenied) {
		t.Fatal("mutable file input accepted", err)
	}
}
