package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

func TestSystemHistoryOutputPreservesResultsWithoutExpansion(t *testing.T) {
	for _, fixture := range []struct{ name, result string }{
		{"deep", strings.Repeat("[", 6000) + "0" + strings.Repeat("]", 6000)},
		{"html", `"` + strings.Repeat("<", 32768) + `"`},
		{"unicode", `"` + strings.Repeat("\u2028\u2029", 32768) + `"`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "workflows")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			original := []byte(`{"id":"output-fixture","action":"discover","state":"failed","result":` + fixture.result + `}`)
			file := filepath.Join(directory, "output-fixture.json")
			if err := os.WriteFile(file, original, 0600); err != nil {
				t.Fatal(err)
			}
			out, err := os.CreateTemp(t.TempDir(), "stdout-*.json")
			if err != nil {
				t.Fatal(err)
			}
			previous := os.Stdout
			os.Stdout = out
			defer func() { os.Stdout = previous; _ = out.Close() }()
			commandErr := systemCommand([]string{"history"}, root)
			os.Stdout = previous
			if err := out.Close(); err != nil {
				t.Fatal(err)
			}
			if commandErr != nil {
				t.Fatal(commandErr)
			}
			info, err := os.Stat(out.Name())
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() > int64(len(original)+1024) {
				t.Fatalf("history output expanded from %d to %d bytes", len(original), info.Size())
			}
			data, err := os.ReadFile(out.Name())
			if err != nil {
				t.Fatal(err)
			}
			var history []workflow.Job
			if err := json.Unmarshal(data, &history); err != nil || len(history) != 1 {
				t.Fatalf("history JSON unreadable: %v", err)
			}
			if !bytes.Equal(history[0].Result, []byte(fixture.result)) || history[0].State != "failed" {
				t.Fatal("complete result or outcome changed")
			}
			retained, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(retained, original) {
				t.Fatal("history export changed the source record")
			}
		})
	}
}
