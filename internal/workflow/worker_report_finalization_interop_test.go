package workflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A selected-function PowerShell fixture produces these reports. Its mocked
// cleanup objects are inert; this is a producer/receiver contract, not evidence
// that a native mutex, uninstaller or recovery journal completed successfully.
func TestWorkerReportFinalizationPowerShellInterop(t *testing.T) {
	directory := os.Getenv("ACCESSWEAVER_WORKER_FINALIZATION_INTEROP")
	if directory == "" {
		t.Skip("source-generated PowerShell finalization fixtures not requested")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("source finalization interop directory is unavailable")
	}
	manifestBytes, err := readWorkflowFile(filepath.Join(directory, "manifest.json"), 16<<10)
	if err != nil {
		t.Fatal("source finalization interop manifest is unavailable")
	}
	type finalizationCase struct {
		Name                   string   `json:"name"`
		ReportingFailure       string   `json:"reportingFailure"`
		FinalizationFailures   []string `json:"finalizationFailures"`
		ExternalEffectsPending bool     `json:"externalEffectsPending"`
	}
	var manifest struct {
		SchemaVersion int                `json:"schemaVersion"`
		SourceSHA256  string             `json:"sourceSHA256"`
		ResultToken   string             `json:"resultToken"`
		Cases         []finalizationCase `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.SchemaVersion != 1 || manifest.ResultToken != workerReportTestToken {
		t.Fatal("source finalization interop manifest is invalid")
	}
	source, err := scripts.ReadFile("windows.ps1")
	if err != nil {
		t.Fatal("embedded finalization source is unavailable")
	}
	digest := sha256.Sum256(source)
	if manifest.SourceSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("PowerShell finalization producer differs from the receiver's embedded source")
	}
	cleanup := []string{"journal-save", "mutex-release", "mutex-dispose"}
	expected := map[string]finalizationCase{
		"cleanup.json":  {Name: "cleanup.json", FinalizationFailures: cleanup, ExternalEffectsPending: true},
		"handoff.json":  {Name: "handoff.json", FinalizationFailures: []string{"uninstaller-start"}, ExternalEffectsPending: true},
		"fallback.json": {Name: "fallback.json", ReportingFailure: "result-too-large", FinalizationFailures: cleanup, ExternalEffectsPending: true},
	}
	if len(manifest.Cases) != len(expected) {
		t.Fatal("source finalization interop manifest omitted cases")
	}
	seen := make(map[string]bool)
	for _, fixture := range manifest.Cases {
		want, known := expected[fixture.Name]
		if !known || seen[fixture.Name] || fixture.ReportingFailure != want.ReportingFailure || !slices.Equal(fixture.FinalizationFailures, want.FinalizationFailures) || fixture.ExternalEffectsPending != want.ExternalEffectsPending {
			t.Fatal("source finalization interop case selection is invalid")
		}
		seen[fixture.Name] = true
		data, err := readWorkflowFile(filepath.Join(directory, fixture.Name), 32<<10)
		if err != nil || validateResult(data) != nil {
			t.Fatal("source finalization report is unavailable, unbounded or invalid JSON")
		}
		before := append([]byte(nil), data...)
		report, err := decodeWorkerReport(data, manifest.ResultToken)
		if err != nil || report.reportingFailure != want.ReportingFailure || !slices.Equal(report.finalizationFailures, want.FinalizationFailures) || report.externalEffectsPending != want.ExternalEffectsPending || !bytes.Equal(before, data) {
			t.Fatal("actual PowerShell finalization output did not satisfy the Go worker contract")
		}
		failure := report.failure()
		if !errors.Is(failure, ErrWorkflowCleanup) || errors.Is(failure, ErrWorkflowPersistence) != (fixture.Name != "handoff.json") || errors.Is(failure, ErrWorkflowResult) != (want.ReportingFailure != "") {
			t.Fatal("source finalization report lost or invented a failure category")
		}
		var outcome struct {
			OK     bool              `json:"ok"`
			Data   json.RawMessage   `json:"data"`
			Events []json.RawMessage `json:"events"`
		}
		if json.Unmarshal(data, &outcome) != nil || outcome.OK {
			t.Fatal("source finalization failure became a successful report")
		}
		if want.ReportingFailure != "" && (!bytes.Equal(outcome.Data, []byte("null")) || len(outcome.Events) != 0) {
			t.Fatal("source reporting fallback retained a partial success payload")
		}
		if _, err := decodeWorkerReport(data, "fedcba9876543210fedcba9876543210fedcba9876543210"); err == nil {
			t.Fatal("source finalization report could be reused for a different launch")
		}
	}
}
