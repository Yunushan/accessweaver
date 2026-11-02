//go:build darwin

package uiaccess

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDisposableDarwinInheritedACLSession(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_SESSION_TEST") != "1" {
		t.Skip("requires an explicitly opted-in disposable hosted Mac")
	}
	if runtime.GOOS != "darwin" || os.Geteuid() == 0 ||
		os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("cross-user fixture requires an ordinary-user disposable hosted Mac")
	}
	run := func(name string, arguments ...string) []byte {
		t.Helper()
		out, err := exec.Command(name, arguments...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command failed: %s: %v: %s", name, err, out)
		}
		return out
	}
	run("/usr/bin/sudo", "-n", "-u", "nobody", "/usr/bin/true")
	fixture, err := os.MkdirTemp("/private/tmp", "accessweaver-session-acl-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(fixture)
	if err := os.Chmod(fixture, 0755); err != nil {
		t.Fatal(err)
	}
	library := filepath.Join(fixture, "Library")
	cache := filepath.Join(library, "Caches")
	if err := os.Mkdir(library, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", fixture)
	t.Setenv("LC_ALL", "C")
	run("/bin/chmod", "+a", "everyone allow read,execute,readattr,readextattr,readsecurity,file_inherit,directory_inherit", cache)
	parentACL := run("/bin/ls", "-lde", cache)
	credential := strings.Repeat("s", 43) // Public fixture data, never a real session.
	launcher, err := New("http://127.0.0.1:45678", credential)
	if err != nil {
		t.Fatal(err)
	}
	defer launcher.Close()
	page, err := os.ReadFile(launcher.Path)
	if err != nil || !bytes.Contains(page, []byte("#accessweaver-session="+credential)) {
		t.Fatal("owner could not read its bound fixture credential", err)
	}
	fileInfo, err := os.Stat(launcher.Path)
	if err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(filepath.Dir(launcher.Path))
	if err != nil || fileInfo.Mode().Perm() != 0600 || dirInfo.Mode().Perm() != 0700 {
		t.Fatal("fixture did not preserve private POSIX modes", err)
	}
	foreign := exec.Command("/usr/bin/sudo", "-n", "-u", "nobody", "/usr/bin/env", "LC_ALL=C", "/bin/cat", launcher.Path)
	foreignPage, foreignErr := foreign.CombinedOutput()
	baseline := os.Getenv("ACCESSWEAVER_EXPECT_DARWIN_SESSION_BASELINE_LEAK") == "1"
	if baseline {
		if foreignErr != nil || !bytes.Contains(foreignPage, []byte(credential)) {
			t.Fatal("original source did not reproduce the cross-user credential disclosure", foreignErr)
		}
	} else {
		exit, ok := foreignErr.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || !bytes.Contains(foreignPage, []byte("Permission denied")) || bytes.Contains(foreignPage, []byte(credential)) {
			t.Fatal("other OS user did not receive the expected permission denial")
		}
		if err := launcher.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(launcher.Path); !os.IsNotExist(err) {
			t.Fatal("credential retained after normal cleanup", err)
		}
		// A mutation ACL on an existing parent must be rejected without removing it.
		run("/bin/chmod", "+a", "everyone allow write", cache)
		mutationACL := run("/bin/ls", "-lde", cache)
		if _, err := New("http://127.0.0.1:45678", credential); err == nil {
			t.Fatal("mutable ACL parent accepted")
		}
		if !bytes.Equal(mutationACL, run("/bin/ls", "-lde", cache)) {
			t.Fatal("existing cache ACL changed during refusal")
		}
		run("/bin/chmod", "-a", "everyone allow write", cache)
	}
	if !bytes.Equal(parentACL, run("/bin/ls", "-lde", cache)) {
		t.Fatal("existing cache ACL was changed")
	}
	report := os.Getenv("ACCESSWEAVER_DARWIN_SESSION_REPORT")
	if report != "" {
		data, err := json.MarshalIndent(map[string]any{
			"passed": true, "goos": runtime.GOOS, "goarch": runtime.GOARCH,
			"sourceRevision": os.Getenv("GITHUB_SHA"), "baselineLeakExpectedAndObserved": baseline,
			"privatePOSIXModesPreserved": true, "ownerCredentialReadPassed": true,
			"foreignCredentialReadDenied": !baseline, "cacheACLUnchanged": true,
			"mutationACLRejected": !baseline, "credentialCleanupPassed": !baseline,
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(report, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
