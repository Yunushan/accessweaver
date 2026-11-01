package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetadataCommandsDoNotCreateUserState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	t.Setenv("ACCESSWEAVER_HOME", root)
	for _, args := range [][]string{{"version", "--json"}, {"managed", "status"}, {"managed"}, {"system", "check-version", "v0.1.0-alpha"}, {"system", "operations"}, {"help"}} {
		if err := execute(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("%v wrote user state: %v", args, err)
		}
	}
	if err := execute([]string{"version", "unexpected"}); err == nil {
		t.Fatal("unknown version option accepted")
	}
}

func TestSystemRequestWindowsEncodingAndSize(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "request.json")
	data := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"action":"discover"}`)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := systemCommand([]string{"preview", path}, root); err != nil {
		t.Fatalf("PowerShell UTF8 request rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"action":"discover"}`+strings.Repeat(" ", 1<<20)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := systemCommand([]string{"preview", path}, root); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized request accepted: %v", err)
	}
}
