package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const workflowHistoryProbeArgument = "--workflow-history-read-probe-v1"

type workflowHistoryProbeRequest struct {
	Version  int    `json:"version"`
	Root     string `json:"root"`
	Snapshot string `json:"snapshot"`
	Cursor   string `json:"cursor"`
	FirstRef string `json:"firstRef"`
	Revision string `json:"revision"`
}

// A native, source-owned reader process demonstrates that references and index
// cursors survive process boundaries. Its stdout protocol is exactly two bytes;
// it never executes a worker or changes user records.
func TestWorkflowHistoryProcessProbeHelper(t *testing.T) {
	for i, arg := range os.Args {
		if arg != "--" {
			continue
		}
		if len(os.Args[i+1:]) != 1 || os.Args[i+1] != workflowHistoryProbeArgument {
			return
		}
		os.Exit(workflowHistoryRunProbe())
	}
}
func workflowHistoryRunProbe() int {
	// The child owns this watchdog. The parent performs one consuming Run/Wait
	// and never signals a potentially retired numeric process identity.
	timer := time.AfterFunc(30*time.Second, func() { os.Exit(76) })
	defer timer.Stop()
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(raw) > 4096 {
		return 71
	}
	var request workflowHistoryProbeRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Version != 1 || !filepath.IsAbs(request.Root) {
		return 71
	}
	root, err := os.Lstat(request.Root)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return 71
	}
	m := New(request.Root)
	page, err := m.HistoryPage(context.Background(), HistoryPageQuery{Limit: 1, Cursor: request.Cursor, Snapshot: request.Snapshot})
	if err != nil || page.Inventory.Snapshot != request.Snapshot || page.Inventory.Count != 2 || len(page.Items) != 1 || page.Items[0].RecordRef == request.FirstRef || page.NextCursor != "" {
		return 72
	}
	content, err := m.ReadHistoryRecordRaw(context.Background(), request.FirstRef, request.Revision)
	if err != nil || workflowHistoryIntegrationDigest(content) != request.Revision {
		return 73
	}
	if n, err := os.Stdout.Write([]byte{'o', 'k'}); err != nil || n != 2 {
		return 74
	}
	return 0
}

type workflowHistoryProbeOutput struct {
	data  [2]byte
	count int
}

func (out *workflowHistoryProbeOutput) Write(data []byte) (int, error) {
	if len(data) > len(out.data)-out.count {
		return 0, io.ErrShortWrite
	}
	copy(out.data[out.count:], data)
	out.count += len(data)
	return len(data), nil
}
func TestWorkflowHistoryInventoryCursorAndReferenceAcrossNativeProcess(t *testing.T) {
	first, second := strings.Repeat("f", 48), strings.Repeat("1", 48)
	root := workflowHistoryIntegrationSeed(t, map[string][]byte{first + ".json": workflowHistoryIntegrationJob(t, first, "first"), second + ".json": workflowHistoryIntegrationJob(t, second, "second")})
	m := New(root)
	captured, err := m.CaptureHistoryInventory(context.Background())
	if err != nil {
		t.Fatal("source process inventory capture unavailable")
	}
	page, err := m.HistoryPage(context.Background(), HistoryPageQuery{Limit: 1, Snapshot: captured.Snapshot})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatal("source process inventory cursor unavailable")
	}
	request, err := json.Marshal(workflowHistoryProbeRequest{1, root, captured.Snapshot, page.NextCursor, page.Items[0].RecordRef, page.Items[0].Revision})
	if err != nil || len(request) > 4096 {
		t.Fatal("source process inventory request exceeded bound")
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal("source Go test image unavailable")
	}
	output := &workflowHistoryProbeOutput{}
	child := exec.Command(image, "-test.run=^TestWorkflowHistoryProcessProbeHelper$", "--", workflowHistoryProbeArgument)
	child.Stdin = bytes.NewReader(request)
	child.Stdout = output
	child.Stderr = io.Discard
	if child.Run() != nil || output.count != 2 || string(output.data[:]) != "ok" {
		t.Fatal("independent native reader did not resolve the captured cursor and exact reference")
	}
}
