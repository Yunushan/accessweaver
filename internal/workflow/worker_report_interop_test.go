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
	"testing"
)

// Only a selected-function PowerShell test run creates these inert fixtures.
// This opt-in belongs to tests, never to production execution or native policy.
func TestWorkerReportPowerShellInterop(t *testing.T) {
	directory := os.Getenv("ACCESSWEAVER_WORKER_RESULT_INTEROP")
	if directory == "" {
		t.Skip("source-generated PowerShell report fixtures not requested")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("source interop directory is unavailable")
	}
	manifestBytes, err := readWorkflowFile(filepath.Join(directory, "manifest.json"), 16<<10)
	if err != nil {
		t.Fatal("source interop manifest is unavailable")
	}
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		SourceSHA256  string `json:"sourceSHA256"`
		ResultToken   string `json:"resultToken"`
		Cases         []struct {
			Name             string `json:"name"`
			ReportingFailure string `json:"reportingFailure"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || manifest.SchemaVersion != 1 || manifest.ResultToken != workerReportTestToken {
		t.Fatal("source interop manifest is invalid")
	}
	if decoder.Decode(new(any)) != io.EOF {
		t.Fatal("source interop manifest contains trailing data")
	}
	source, err := scripts.ReadFile("windows.ps1")
	if err != nil {
		t.Fatal("embedded source unavailable")
	}
	digest := sha256.Sum256(source)
	if manifest.SourceSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("PowerShell producer differs from the receiver's embedded source")
	}
	expected := map[string]string{"normal.json": "", "too-large.json": "result-too-large", "too-deep.json": "result-depth"}
	if len(manifest.Cases) != len(expected) {
		t.Fatal("source interop manifest omitted cases")
	}
	seen := map[string]bool{}
	for _, fixture := range manifest.Cases {
		want, known := expected[fixture.Name]
		if !known || seen[fixture.Name] || fixture.ReportingFailure != want {
			t.Fatal("source interop case selection is invalid")
		}
		seen[fixture.Name] = true
		data, err := readWorkflowFile(filepath.Join(directory, fixture.Name), 32<<10)
		if err != nil || validateResult(data) != nil {
			t.Fatal("source-produced report is missing, unbounded or invalid JSON")
		}
		report, err := decodeWorkerReport(data, manifest.ResultToken)
		if err != nil || report.reportingFailure != want {
			t.Fatal("real PowerShell output did not satisfy the Go worker envelope")
		}
		var outcome struct {
			OK     bool              `json:"ok"`
			Data   json.RawMessage   `json:"data"`
			Events []json.RawMessage `json:"events"`
		}
		if json.Unmarshal(data, &outcome) != nil {
			t.Fatal("source report outcome could not be decoded")
		}
		if want == "" {
			if !outcome.OK || report.failure() != nil {
				t.Fatal("normal source report was changed into failure")
			}
		} else if outcome.OK || !errors.Is(report.failure(), ErrWorkflowResult) || !bytes.Equal(outcome.Data, []byte("null")) || len(outcome.Events) != 0 {
			t.Fatal("source reporting refusal was truncated into success or lost its category")
		}
		if _, err := decodeWorkerReport(data, "fedcba9876543210fedcba9876543210fedcba9876543210"); err == nil {
			t.Fatal("source report could be reused for a different launch")
		}
	}
}
