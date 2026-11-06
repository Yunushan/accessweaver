package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

func TestSystemHistoryBrowserRetainedStageKeepsExactCLIReads(t *testing.T) {
	raw := []byte{0xff, '{', 0, 'X'}
	root, manager := systemHistoryBrowserFixture(t, map[string][]byte{"source-malformed.json": raw})
	inventory := systemHistoryBrowserCapture(t, manager)
	page := systemHistoryBrowserList(t, manager)
	if len(page.Items) != 1 {
		t.Fatal("source CLI prior captured record unavailable")
	}
	row := page.Items[0]
	stage := filepath.Join(root, ".workflow-history-"+strings.Repeat("c", 48)+".tmp")
	retained := []byte("retained-source-cli-stage-not-an-owner-proof")
	if err := os.WriteFile(stage, retained, 0600); err != nil {
		t.Fatal("source CLI stage unavailable")
	}
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal("source CLI metadata count unavailable")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			manager = systemHistoryBrowserManager(root)
		}
		var output bytes.Buffer
		err := runSystemHistory(context.Background(), manager, []string{"capture"}, &output)
		if !errors.Is(err, workflow.ErrHistoryStagingPending) || err.Error() != workflow.ErrHistoryStagingPending.Error() || output.Len() != 0 {
			t.Fatal("CLI retained-stage refusal lost fixed cause or wrote success")
		}
		after, readErr := os.ReadDir(root)
		if readErr != nil || len(after) != len(before) {
			t.Fatal("CLI refused capture allocated another stage/control object")
		}
		data, readErr := os.ReadFile(stage)
		if readErr != nil || !bytes.Equal(data, retained) {
			t.Fatal("CLI refused capture modified retained evidence")
		}
		output.Reset()
		if err := runSystemHistory(context.Background(), manager, []string{"list", "--snapshot", inventory.Snapshot}, &output); err != nil || !bytes.Contains(output.Bytes(), []byte(row.RecordRef)) {
			t.Fatal("CLI retained-stage refusal blocked exact old snapshot")
		}
		output.Reset()
		if err := runSystemHistory(context.Background(), manager, []string{"export", row.RecordRef, "--revision", row.Revision}, &output); err != nil || !bytes.Equal(output.Bytes(), raw) {
			t.Fatal("CLI retained-stage refusal blocked or changed exact raw bytes")
		}
	}
}
