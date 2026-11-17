//go:build windows

package servicehost

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceConfigUsesLocalRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.json")
	valid := []byte(`{"name":"AccessWeaver-zapret2","binary":"binary.exe","args":[],"directory":"components","logPath":"logs/out.log"}`)
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readLocalServiceConfig(path)
	if err != nil || cfg.Name != "AccessWeaver-zapret2" {
		t.Fatalf("local configuration unavailable: %v", err)
	}
	for _, input := range []string{dir, `\\example.invalid\share\service.json`, `\\.\NUL`} {
		if got, err := readLocalServiceConfig(input); err == nil || got.Name != "" {
			t.Fatal("non-local or non-regular configuration accepted")
		}
	}
}
