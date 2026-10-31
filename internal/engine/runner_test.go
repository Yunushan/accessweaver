package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/Yunushan/accessweaver/internal/profile"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCatalogPlatformConsistency(t *testing.T) {
	items := Catalog()
	if len(items) < 8 {
		t.Fatalf("expected broad catalog; got %d", len(items))
	}
	for _, d := range items {
		if d.ID == "" || len(d.Platforms) == 0 || d.Source == "" {
			t.Fatalf("incomplete %s", d.ID)
		}
	}
}
func TestNoSilentAppFiltering(t *testing.T) {
	p := profile.New("test-profile", "Test", "spoofdpi")
	p.Routing.Applications = []string{"example.exe"}
	_, _, err := Prepare(p, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "application routing") {
		t.Fatalf("expected explicit rejection, got %v", err)
	}
}
func TestNoSilentUnsupportedExclusion(t *testing.T) {
	p := profile.New("test-profile", "Test", "spoofdpi")
	p.Routing.ExcludeDomains = []string{"example.com"}
	_, _, err := Prepare(p, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "exclusion") {
		t.Fatalf("expected explicit rejection, got %v", err)
	}
}
func TestPrepareHostListAndChecksum(t *testing.T) {
	name := "nfqws2"
	selected := "zapret2"
	if runtime.GOOS == "darwin" {
		name = "tpws"
		selected = "zapret"
	}
	if runtime.GOOS == "windows" {
		name = "winws2.exe"
	}
	root := t.TempDir()
	bin := filepath.Join(root, name)
	if err := os.WriteFile(bin, []byte("fake-binary-test"), 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("fake-binary-test"))
	p := profile.New("test-profile", "Test", selected)
	p.Binary = bin
	p.SHA256 = hex.EncodeToString(sum[:])
	p.Args = []string{"--lua-desync=multisplit:pos=2"}
	if selected == "zapret" {
		p.Args = []string{"--socks", "--port=1080"}
	}
	p.Routing.IncludeDomains = []string{"discord.com"}
	p.Routing.ExcludeDomains = []string{"microsoft.com"}
	got, args, err := Prepare(p, root)
	if err != nil {
		t.Fatal(err)
	}
	if got != bin {
		t.Fatalf("binary %s", got)
	}
	wantCount := len(p.Args) + 2
	if selected == "zapret" {
		wantCount++
	}
	if len(args) != wantCount {
		t.Fatalf("unexpected args: %v", args)
	}
	file := filepath.Join(root, "generated", "test-profile-exclude.txt")
	content, err := os.ReadFile(file)
	if runtime.GOOS == "windows" {
		if err != nil || string(content) != "microsoft.com\n" {
			t.Fatalf("unexpected excludes %q %v", content, err)
		}
	} else {
		if !os.IsNotExist(err) {
			t.Fatalf("Unix inline rules should not create private unreadable lists: %v", err)
		}
		if !hasOption(args, "--hostlist-exclude-domains") {
			t.Fatal("missing inline exclusions")
		}
	}
	p.SHA256 = strings.Repeat("0", 64)
	_, _, err = Prepare(p, root)
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("wanted checksum error: %v", err)
	}
}
