package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func systemHistoryBrowserManager(root string) *workflow.Manager {
	return workflow.NewWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
}

func systemHistoryBrowserFixture(t *testing.T, records map[string][]byte) (string, *workflow.Manager) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "workflows")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range records {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, systemHistoryBrowserManager(root)
}

func systemHistoryBrowserCapture(t *testing.T, manager *workflow.Manager) workflow.HistoryInventory {
	t.Helper()
	var output bytes.Buffer
	if err := runSystemHistory(context.Background(), manager, []string{"capture"}, &output); err != nil {
		t.Fatal("CLI could not explicitly capture its source inventory")
	}
	var inventory workflow.HistoryInventory
	if json.Unmarshal(output.Bytes(), &inventory) != nil || len(inventory.Snapshot) != 48 {
		t.Fatal("CLI capture did not return a durable snapshot")
	}
	return inventory
}

func systemHistoryBrowserList(t *testing.T, manager *workflow.Manager, args ...string) workflow.HistoryPage {
	t.Helper()
	var output bytes.Buffer
	if err := runSystemHistory(context.Background(), manager, append([]string{"list"}, args...), &output); err != nil {
		t.Fatal("CLI could not read the captured page")
	}
	var page workflow.HistoryPage
	if json.Unmarshal(output.Bytes(), &page) != nil {
		t.Fatal("CLI page did not contain valid bounded metadata")
	}
	return page
}

func systemHistoryBrowserSHA(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func systemHistoryBrowserFind(t *testing.T, page workflow.HistoryPage, revision string) workflow.HistoryRecordSummary {
	t.Helper()
	for _, item := range page.Items {
		if item.Revision == revision {
			return item
		}
	}
	t.Fatal("source row was not present in the CLI page")
	return workflow.HistoryRecordSummary{}
}

func TestSystemHistoryBrowserParserIsStrictBeforeStorage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	manager := systemHistoryBrowserManager(root)
	for _, args := range [][]string{
		{"export", "abc", "--revision", strings.Repeat("a", 64), "--out"}, {"export", "abc", "--revision", strings.Repeat("a", 64), "--out", ""}, {"export", "abc", "--revision", strings.Repeat("a", 64), "--out", "path", "--out", "again"}, {"get", "abc", "--revision", strings.Repeat("a", 64), "--out", "path"},
		{"unknown"}, {"capture", "extra"}, {"list", "extra"}, {"list", "--limit"}, {"list", "--limit", "0"}, {"list", "--limit", "129"}, {"list", "--limit", "+1"}, {"list", "--limit", "1", "--limit", "2"}, {"list", "--cursor", ""}, {"list", "--cursor", "../PRIVATE_CURSOR"}, {"list", "--snapshot", strings.Repeat("A", 48)}, {"list", "--unknown", "PRIVATE_VALUE"}, {"get", "abc"}, {"get", "abc", "--revision", "short"}, {"export", "abc", "--revision", ""}, {"get", "../PRIVATE_PATH", "--revision", strings.Repeat("a", 64)}, {"get", "abc", "--revision", strings.Repeat("a", 64), "extra"},
	} {
		var output bytes.Buffer
		err := runSystemHistory(context.Background(), manager, args, &output)
		if !errors.Is(err, workflow.ErrHistoryInvalidRequest) || output.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_") {
			t.Fatal("invalid CLI history arguments reached storage or exposed input")
		}
		if _, statErr := os.Stat(root); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("CLI argument refusal created a root or coordination file")
		}
	}
	for _, args := range [][]string{nil, {"capture"}, {"list"}, {"list", "--limit", "128", "--cursor", "YQ", "--snapshot", strings.Repeat("a", 48)}, {"get", "YQ", "--revision", ""}, {"export", "YQ", "--revision", strings.Repeat("a", 64)}} {
		if _, err := parseSystemHistory(args); err != nil {
			t.Fatal("documented CLI history syntax was rejected")
		}
	}
	var output bytes.Buffer
	err := runSystemHistory(context.Background(), manager, []string{"list"}, &output)
	if !errors.Is(err, workflow.ErrHistoryInventoryNeeded) || output.Len() != 0 {
		t.Fatal("missing catalog was silently initialized or represented as a complete empty page")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only CLI history initialized its missing root")
	}
}

func TestSystemHistoryBrowserReferencesSurviveFreshManagerAndExportExactBytes(t *testing.T) {
	id := strings.Repeat("a", 48)
	original := []byte("{\n\"id\":\"PRIVATE_JOB_IDENTIFIER\",\"action\":\"discover\",\"state\":\"failed\",\"error\":\"PRIVATE_JOB_ERROR\",\"result\":{\"value\":\"PRIVATE_JOB_RESULT\"}}\n")
	other := []byte(`{"id":"other","action":"discover","state":"succeeded"}`)
	opaque := []byte{0xff, '{', 0, 'Z'}
	root, manager := systemHistoryBrowserFixture(t, map[string][]byte{id + ".json": original, "PRIVATE_JOB_IDENTIFIER.json": other, "opaque.json": opaque})
	inventory := systemHistoryBrowserCapture(t, manager)
	// The CLI constructs a new Manager on every invocation. No in-memory map
	// from capture is available to resolve these durable observed-file refs.
	fresh := systemHistoryBrowserManager(root)
	page := systemHistoryBrowserList(t, fresh, "--snapshot", inventory.Snapshot, "--limit", "128")
	row := systemHistoryBrowserFind(t, page, systemHistoryBrowserSHA(original))
	if row.ID != id || row.ID == "PRIVATE_JOB_IDENTIFIER" {
		t.Fatal("CLI catalog identity came from persisted Job.ID instead of the observed filename")
	}
	var detailOutput bytes.Buffer
	if err := runSystemHistory(context.Background(), fresh, []string{"get", row.RecordRef, "--revision", row.Revision}, &detailOutput); err != nil {
		t.Fatal("fresh Manager could not resolve reviewed selected detail")
	}
	var detail workflow.HistoryRecordDetail
	if json.Unmarshal(detailOutput.Bytes(), &detail) != nil || detail.Job == nil || detail.Job.ID != "PRIVATE_JOB_IDENTIFIER" || !bytes.Contains(detail.Job.Result, []byte("PRIVATE_JOB_RESULT")) {
		t.Fatal("selected CLI detail did not preserve complete explicit private values")
	}
	for _, selected := range []struct {
		row  workflow.HistoryRecordSummary
		data []byte
	}{{row, original}, {systemHistoryBrowserFind(t, page, systemHistoryBrowserSHA(opaque)), opaque}} {
		var raw bytes.Buffer
		if err := runSystemHistory(context.Background(), systemHistoryBrowserManager(root), []string{"export", selected.row.RecordRef, "--revision", selected.row.Revision}, &raw); err != nil || !bytes.Equal(raw.Bytes(), selected.data) {
			t.Fatal("CLI raw export changed bytes, added a newline or followed persisted Job.ID")
		}
	}
	var legacy bytes.Buffer
	if err := runSystemHistory(context.Background(), fresh, nil, &legacy); err != nil {
		t.Fatal("additive commands broke legacy bare history")
	}
	var jobs []workflow.Job
	if json.Unmarshal(legacy.Bytes(), &jobs) != nil || len(jobs) != 2 {
		t.Fatal("bare history stopped being the complete legacy decoded array")
	}
	if err := os.WriteFile(filepath.Join(root, "workflows", id+".json"), []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	var stale bytes.Buffer
	err := runSystemHistory(context.Background(), fresh, []string{"export", row.RecordRef, "--revision", row.Revision}, &stale)
	if !errors.Is(err, workflow.ErrHistoryInventoryStale) || stale.Len() != 0 || strings.Contains(err.Error(), root) {
		t.Fatal("CLI exported changed bytes under a stale review or exposed the private root")
	}
}

type systemHistorySizedWriter struct {
	bytes.Buffer
	largest int
}

func (w *systemHistorySizedWriter) Write(data []byte) (int, error) {
	w.largest = max(w.largest, len(data))
	return w.Buffer.Write(data)
}

type systemHistoryFailureWriter struct {
	failure error
	short   bool
}

func (w systemHistoryFailureWriter) Write([]byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return 0, w.failure
}

func TestSystemHistoryBrowserWritesAreBoundedAndFailuresPrivate(t *testing.T) {
	data := []byte(`{"id":"legacy","action":"discover","state":"failed","result":"` + strings.Repeat("<", 256<<10) + `"}`)
	_, manager := systemHistoryBrowserFixture(t, map[string][]byte{"large.json": data})
	systemHistoryBrowserCapture(t, manager)
	row := systemHistoryBrowserFind(t, systemHistoryBrowserList(t, manager), systemHistoryBrowserSHA(data))
	for _, command := range []string{"get", "export"} {
		output := &systemHistorySizedWriter{}
		if err := runSystemHistory(context.Background(), manager, []string{command, row.RecordRef, "--revision", row.Revision}, output); err != nil || output.largest > 32<<10 || output.Len() > len(data)+4096 {
			t.Fatal("CLI selected output expanded data or issued an aggregate write")
		}
		private := errors.New("PRIVATE_HISTORY_WRITER")
		for _, writer := range []systemHistoryFailureWriter{{failure: private}, {short: true}} {
			err := runSystemHistory(context.Background(), manager, []string{command, row.RecordRef, "--revision", row.Revision}, writer)
			if err == nil || strings.Contains(err.Error(), "PRIVATE_HISTORY_") || writer.short && !errors.Is(err, io.ErrShortWrite) || !writer.short && !errors.Is(err, private) {
				t.Fatal("CLI output failure was hidden or exposed private writer detail")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ended bytes.Buffer
	if err := runSystemHistory(ctx, manager, []string{"export", row.RecordRef, "--revision", row.Revision}, &ended); !errors.Is(err, context.Canceled) || ended.Len() != 0 {
		t.Fatal("ended CLI export wrote private content")
	}
}

func TestSystemHistoryBrowserMetadataOnlyDetailAndFixedErrors(t *testing.T) {
	root, manager := systemHistoryBrowserFixture(t, nil)
	if err := os.Mkdir(filepath.Join(root, "workflows", "special.json"), 0700); err != nil {
		t.Fatal(err)
	}
	systemHistoryBrowserCapture(t, manager)
	page := systemHistoryBrowserList(t, systemHistoryBrowserManager(root))
	if len(page.Items) != 1 || page.Items[0].RawAvailable || page.Items[0].Revision != "" {
		t.Fatal("protected source entry did not remain visible as metadata")
	}
	var output bytes.Buffer
	if err := runSystemHistory(context.Background(), manager, []string{"get", page.Items[0].RecordRef, "--revision", ""}, &output); err != nil {
		t.Fatal("CLI could not inspect explicitly reviewed metadata-only detail")
	}
	var detail workflow.HistoryRecordDetail
	if json.Unmarshal(output.Bytes(), &detail) != nil || detail.Job != nil || detail.RawAvailable {
		t.Fatal("CLI metadata-only selection adopted an unknown source")
	}
	for _, category := range []error{workflow.ErrHistoryInvalidRequest, workflow.ErrHistoryInventoryNeeded, workflow.ErrHistoryInventoryStale, workflow.ErrHistoryRecordUnavailable, workflow.ErrHistoryCapacity, workflow.ErrWorkflowBusy, workflow.ErrHistoryUnavailable} {
		private := errors.New("PRIVATE_HISTORY_STORAGE")
		err := systemHistoryError(errors.Join(category, private))
		if !errors.Is(err, category) || !errors.Is(err, private) || strings.Contains(err.Error(), "PRIVATE_HISTORY_") {
			t.Fatal("new CLI history errors lost categories or exposed private causes")
		}
	}
}

type systemHistoryExportFixture struct {
	bytes.Buffer
	writeErr, syncErr, closeErr error
	cancel                      context.CancelFunc
	writes, syncs, closes       int
}

func (f *systemHistoryExportFixture) Write(data []byte) (int, error) {
	f.writes++
	if f.writeErr != nil {
		n := min(3, len(data))
		_, _ = f.Buffer.Write(data[:n])
		return n, f.writeErr
	}
	n, err := f.Buffer.Write(data)
	if f.cancel != nil {
		f.cancel()
	}
	return n, err
}
func (f *systemHistoryExportFixture) Sync() error  { f.syncs++; return f.syncErr }
func (f *systemHistoryExportFixture) Close() error { f.closes++; return f.closeErr }

func TestSystemHistoryBrowserFileExportIsExclusiveAndByteExact(t *testing.T) {
	data := []byte{0xff, 0, '{', 'X', '\n'}
	root, manager := systemHistoryBrowserFixture(t, map[string][]byte{"opaque.json": data})
	systemHistoryBrowserCapture(t, manager)
	row := systemHistoryBrowserFind(t, systemHistoryBrowserList(t, manager), systemHistoryBrowserSHA(data))
	outputPath := filepath.Join(t.TempDir(), "PRIVATE_SELECTED_OUTPUT.bin")
	args := []string{"export", row.RecordRef, "--revision", row.Revision, "--out", outputPath}
	var stdout bytes.Buffer
	if err := runSystemHistory(context.Background(), manager, args, &stdout); err != nil {
		t.Fatal("explicit output-file export failed")
	}
	stored, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(stored, data) || stdout.Len() != 0 {
		t.Fatal("output-file export decoded bytes or wrote an unexpected stdout envelope")
	}
	err = runSystemHistory(context.Background(), manager, args, &stdout)
	if !errors.Is(err, os.ErrExist) || strings.Contains(err.Error(), outputPath) || strings.Contains(err.Error(), "PRIVATE_") {
		t.Fatal("output-file export replaced an existing destination or exposed its path")
	}
	retained, readErr := os.ReadFile(outputPath)
	if readErr != nil || !bytes.Equal(retained, data) {
		t.Fatal("existing output file changed after exclusive-create refusal")
	}
	if err := os.WriteFile(filepath.Join(root, "workflows", "opaque.json"), []byte("changed source"), 0600); err != nil {
		t.Fatal(err)
	}
	missingOutput := filepath.Join(t.TempDir(), "not-created.bin")
	args[len(args)-1] = missingOutput
	err = runSystemHistory(context.Background(), manager, args, &stdout)
	if !errors.Is(err, workflow.ErrHistoryInventoryStale) {
		t.Fatal("stale output-file export bypassed source preflight")
	}
	if _, err := os.Stat(missingOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale source preflight created an output file")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writeSystemHistoryExportFile(ctx, missingOutput, data); !errors.Is(err, context.Canceled) {
		t.Fatal("ended file export did not refuse before create")
	}
	if _, err := os.Stat(missingOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ended file export created a destination")
	}
}

func TestSystemHistoryBrowserFileExportChecksWriteSyncClose(t *testing.T) {
	data := bytes.Repeat([]byte("x"), (64<<10)+10)
	private := errors.New("PRIVATE_EXPORT_IO")
	for _, phase := range []string{"normal", "write", "sync", "close", "cancel"} {
		ctx, cancel := context.WithCancel(context.Background())
		fixture := &systemHistoryExportFixture{}
		switch phase {
		case "write":
			fixture.writeErr = private
		case "sync":
			fixture.syncErr = private
		case "close":
			fixture.closeErr = private
		case "cancel":
			fixture.cancel = cancel
		}
		err := finishSystemHistoryExport(ctx, fixture, data)
		cancel()
		if fixture.closes != 1 {
			t.Fatal("file output failed to observe its one owned close")
		}
		switch phase {
		case "normal":
			if err != nil || fixture.syncs != 1 || !bytes.Equal(fixture.Bytes(), data) {
				t.Fatal("normal file output was not written, synced and closed")
			}
		case "write":
			if !errors.Is(err, private) || fixture.syncs != 0 || fixture.Len() != 3 {
				t.Fatal("failed file write lost its partial bytes or original failure")
			}
		case "sync", "close":
			if !errors.Is(err, private) || fixture.syncs != 1 || !bytes.Equal(fixture.Bytes(), data) {
				t.Fatal("file sync/close failure was hidden or discarded retained output")
			}
		case "cancel":
			if !errors.Is(err, context.Canceled) || fixture.syncs != 0 || fixture.Len() != 32<<10 {
				t.Fatal("canceled file output continued writing or skipped checked close")
			}
		}
	}
}
