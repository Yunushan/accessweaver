package profile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateProfile(t *testing.T) {
	p := New("discord-test", "Discord testing", "zapret2")
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*Profile)
	}{
		{"path traversal", func(p *Profile) { p.ID = "../root" }},
		{"empty name", func(p *Profile) { p.Name = "  " }},
		{"invalid domain", func(p *Profile) { p.Routing.IncludeDomains = []string{"example.com;rm -rf"} }},
		{"duplicate", func(p *Profile) { p.Routing.IncludeDomains = []string{"example.com", "EXAMPLE.COM"} }},
		{"include-exclude collision", func(p *Profile) {
			p.Routing.IncludeDomains = []string{"example.com"}
			p.Routing.ExcludeDomains = []string{"example.com"}
		}},
		{"old schema", func(p *Profile) { p.Version = 0 }},
		{"invalid hash", func(p *Profile) { p.SHA256 = "1234" }},
		{"nul arg", func(p *Profile) { p.Args = []string{"hi\x00there"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := p.Copy()
			tc.edit(&v)
			if err := v.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
func TestJSONRejectsUnknownAndTrailing(t *testing.T) {
	base := New("testing", "Testing", "byedpi")
	s := `{"version":1,"id":"testing","name":"Testing","engine":"byedpi","args":[],"routing":{"includeDomains":[],"excludeDomains":[],"applications":[]},"probe":{"host":"discord.com","port":443,"tls":true,"timeoutSeconds":5},"unknown":true}`
	if _, err := Decode(strings.NewReader(s)); err == nil {
		t.Fatal("expected unknown key rejection")
	}
	if _, err := Decode(strings.NewReader(`{} {}`)); err == nil {
		t.Fatal("expected trailing data rejection")
	}
	_ = base
}
func TestStoreRoundTripAndAtomicReplacement(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := New("sample-one", "Sample One", "byedpi")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	p.Name = "Edited"
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Edited" {
		t.Fatalf("got %q", got.Name)
	}
	info, err := os.Stat(filepath.Join(s.Root, "profiles", "sample-one.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatal("profile is not regular")
	}
	if err := s.Delete(p.ID); err != nil {
		t.Fatal(err)
	}
	items, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatal("expected empty list")
	}
}
func TestSymlinkProfileRejected(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("symlink creation requires privileges on Windows")
	}
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "private.json")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.Root, "profiles", "trap.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(New("trap", "Trap", "byedpi")); err == nil {
		t.Fatal("must not overwrite symlink")
	}
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, []byte("secret")) {
		t.Fatal("symlink target modified")
	}
}

func TestSeedRunsOnceAndPreservesDeletion(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	samples := []Profile{New("sample-one", "Sample", "byedpi")}
	if err := s.Seed(samples); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("sample-one"); err != nil {
		t.Fatal(err)
	}
	if err := s.Seed(samples); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("sample-one"); !os.IsNotExist(err) {
		t.Fatalf("deleted preset returned: %v", err)
	}
}

func TestDecodeRejectsOversizedTrailingWhitespace(t *testing.T) {
	input := `{"version":1,"id":"test-id","name":"Test","engine":"byedpi","args":[],"routing":{},"probe":{"host":"example.com","port":443,"timeoutSeconds":5}}` + strings.Repeat(" ", 1<<20)
	if _, err := Decode(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("size limit: %v", err)
	}
}

func TestProbeRejectsHostlistSyntax(t *testing.T) {
	p := New("probe-test", "Probe", "byedpi")
	p.Probe.Host = "^example.com"
	if err := p.Validate(); err == nil {
		t.Fatal("hostlist prefix accepted for DNS probe")
	}
	p.Probe.Host = "127.0.0.1"
	p.Probe.Port = 0
	if err := p.Validate(); err == nil {
		t.Fatal("zero probe port accepted")
	}
}
