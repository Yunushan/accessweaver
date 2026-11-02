package uiaccess

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrivateLauncherLifecycle(t *testing.T) {
	if err := RequireUnelevated(); err != nil {
		t.Skip("Positive browser-launch test requires a normal desktop token; elevated refusal is tested separately")
	}
	cache := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("LOCALAPPDATA", cache)
	} else if runtime.GOOS == "darwin" {
		t.Setenv("HOME", cache)
	} else {
		t.Setenv("XDG_CACHE_HOME", cache)
	}
	credential := strings.Repeat("s", 43)
	launcher, err := New("http://127.0.0.1:45678", credential)
	if err != nil {
		t.Fatal(err)
	}
	defer launcher.Close()
	if strings.Contains(launcher.URL, credential) || !strings.HasPrefix(launcher.URL, "file:") {
		t.Fatal("credential exposed in browser process argument")
	}
	page, err := os.ReadFile(launcher.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "#accessweaver-session="+credential) || !strings.Contains(string(page), "no-referrer") {
		t.Fatal("private launcher did not bind its session")
	}
	if runtime.GOOS != "windows" {
		file, _ := os.Stat(launcher.Path)
		directory, _ := os.Stat(filepath.Dir(launcher.Path))
		if file.Mode().Perm() != 0600 || directory.Mode().Perm() != 0700 {
			t.Fatal("launcher is not private")
		}
	}
	if err := launcher.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(launcher.Path); !os.IsNotExist(err) {
		t.Fatal("session credential file retained after shutdown", err)
	}
}

func TestLauncherRejectsUnboundDestinationsAndMalformedCredentials(t *testing.T) {
	for _, address := range []string{"https://127.0.0.1:80", "http://evil.invalid:80", "http://user@127.0.0.1:80", "http://127.0.0.1:80?token=other", "http://127.0.0.1:80#other"} {
		if _, err := New(address, strings.Repeat("s", 43)); err == nil {
			t.Fatalf("unbound destination accepted: %s", address)
		}
	}
	if _, err := New("http://127.0.0.1:80", "invalid"); err == nil {
		t.Fatal("malformed credential accepted")
	}
}

func TestElevatedLauncherCannotExposeAControlSession(t *testing.T) {
	if err := RequireUnelevated(); err == nil {
		return
	}
	if _, err := New("http://127.0.0.1:80", strings.Repeat("s", 43)); err == nil {
		t.Fatal("elevated UI session created")
	}
}
