package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedSchemaValidationAndOfflinePolicy(t *testing.T) {
	schema, err := compileSchema("../sbom/schema")
	if err != nil {
		t.Fatal(err)
	}
	var valid any
	if err := json.Unmarshal([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), &valid); err != nil {
		t.Fatal(err)
	}
	if err := validateDocument(schema, valid); err != nil {
		t.Fatal(err)
	}
	invalid := map[string]any{"bomFormat": "CycloneDX", "specVersion": "unsupported", "version": 1}
	if validateDocument(schema, invalid) == nil {
		t.Fatal("unsupported schema version accepted")
	}
	if _, err := (denyLoader{}).Load("https://example.invalid/remote-schema"); err == nil {
		t.Fatal("remote schema loading allowed")
	}
}
func TestChangedSchemaCannotBeUsed(t *testing.T) {
	root := t.TempDir()
	for name := range schemas {
		data, err := os.ReadFile(filepath.Join("../sbom/schema", name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "bom-1.6.schema.json" {
			data = append(data, 10)
		}
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := compileSchema(root); err == nil {
		t.Fatal("changed pinned schema accepted")
	}
}
