//go:build windows

package audit

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// This source-built fixture duplicates only its own existing token. It changes
// no account, privilege, policy, service or filesystem ACL. It never runs as an
// installed product and requires explicit disposable hosted-runner opt-in.
func TestWindowsAuditProcessImpersonationRefused(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Skip("requires opted-in disposable Windows source fixture")
	}
	runtime.LockOSThread()
	// Never return a thread to the Go scheduler unless the context is restored.
	// A goroutine exiting while locked makes the runtime retire that OS thread.
	restored := true
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
	}()
	baseline, err := ProcessProducer(fixtureActorKey())
	if err != nil {
		t.Fatal(err)
	}
	var primary windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &primary); err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(primary, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	if err := windows.SetThreadToken(nil, impersonation); err != nil {
		t.Fatal(err)
	}
	restored = false
	defer func() {
		if !restored {
			if err := windows.RevertToSelf(); err != nil {
				t.Error("could not restore disposable thread context")
				return
			}
			restored = true
		}
	}()
	got, err := ProcessProducer(fixtureActorKey())
	if !errors.Is(err, ErrProcessIdentity) || got != (Producer{}) {
		t.Fatal("impersonated thread attributed to process token", err)
	}
	if err := windows.RevertToSelf(); err != nil {
		t.Fatal("could not restore disposable thread context")
	}
	restored = true
	after, err := ProcessProducer(fixtureActorKey())
	if err != nil || after != baseline {
		t.Fatal("restored process identity differs", err)
	}
}
