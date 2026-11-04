package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditUIDirectOutputsCannotAliasProtectedInputs(t *testing.T) {
	input := filepath.Join(t.TempDir(), "checkpoint.json")
	original := []byte("PRIVATE_INPUT_BYTES")
	if err := os.WriteFile(input, original, 0600); err != nil {
		t.Fatal(err)
	}
	alias, err := os.OpenFile(input, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Close()
	for _, outputs := range [][2]io.Writer{{alias, &bytes.Buffer{}}, {&bytes.Buffer{}, alias}} {
		if err := checkAuditUIOutputs(outputs[0], outputs[1], []string{input}); err == nil {
			t.Fatal("output alias accepted")
		}
	}
	if err := checkAuditUIOutputs(alias, alias, nil); err == nil {
		t.Fatal("mixed checkpoint/startup output accepted")
	}
	data, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("refusal changed source")
	}
}
func TestAuditUIExactOptionsBeforeAnyProfileStoreAccess(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-not-be-created")
	t.Setenv("ACCESSWEAVER_HOME", root)
	for _, args := range [][]string{{"ui"}, {"ui", "--directory", "PRIVATE", "--from", "PRIVATE", "--to", "PRIVATE", "--unknown", "PRIVATE"}, {"ui", "--directory", "PRIVATE", "--from", "PRIVATE", "--from", "PRIVATE"}} {
		if err := auditUICommand(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || bytes.Contains([]byte(err.Error()), []byte("PRIVATE")) {
			t.Fatal("unsafe option handling", err)
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("invalid options reached profile storage")
	}
}
