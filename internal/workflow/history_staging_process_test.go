package workflow

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
)

const workflowHistoryStageSourceArgument = "--workflow-history-stage-source-v1"

// Only an inert Go-test subprocess is accepted. The anonymous bootstrap/control
// pipe carries the synthetic fixture root; argv/environment carry no path or
// private record content. No workflow executor, native worker or vendor runs.
func TestWorkflowHistoryStagingProcessHelper(t *testing.T) {
	marker := -1
	for index, argument := range os.Args {
		if argument == "--" {
			marker = index
			break
		}
	}
	if marker < 0 {
		return
	}
	if len(os.Args[marker+1:]) != 1 || os.Args[marker+1] != workflowHistoryStageSourceArgument {
		os.Exit(90)
	}
	os.Exit(workflowHistoryStagingSourceChild())
}

func workflowHistoryStagingSourceChild() int {
	reader := bufio.NewReaderSize(os.Stdin, 4096)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 4096 {
		return 91
	}
	var request struct {
		Version int
		Root    string
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Version != 1 || !filepath.IsAbs(request.Root) {
		return 91
	}
	named, err := os.Lstat(request.Root)
	if err != nil || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 {
		return 91
	}
	release := make(chan struct{})
	go func() {
		command, err := reader.ReadByte()
		if err != nil {
			os.Exit(98)
		}
		switch command {
		case 'q':
			close(release)
		case 'x':
			// Bypass the capture/active-lease defers deliberately. The sole
			// parent Wait witnesses process exit; it cannot prove the old
			// operation completed or certify every original metadata owner.
			os.Exit(97)
		default:
			os.Exit(98)
		}
	}()
	manager := workflowHistoryStagingSourceManager(request.Root)
	var once sync.Once
	manager.historyStagingHooks = &historyStagingHooks{afterPrepared: func() error {
		once.Do(func() {
			// The production hook runs only after real counted stage writes,
			// Sync, checked Close and prepared reservation publication.
			if n, err := os.Stdout.Write([]byte{'r'}); err != nil || n != 1 {
				os.Exit(94)
			}
		})
		<-release
		return nil
	}}
	if _, err := manager.CaptureHistoryInventory(context.Background()); err != nil {
		return 93
	}
	if n, err := os.Stdout.Write([]byte{'d'}); err != nil || n != 1 {
		return 94
	}
	return 0
}

func workflowHistoryStagingSourceManager(root string) *Manager {
	guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	return NewWithGuard(root, guard)
}

// Reuse the already-reviewed lifetime holder: a control/release/Kill decision
// always precedes its sole Wait; after Wait begins no later signal is possible.
// Its cleanup preserves the root on an unconfirmed child or Manager join.
func workflowHistoryStagingLaunch(t *testing.T, fixture *workflowStoreSourceFixture) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("source staging test image unavailable")
	}
	fixture.output = &workflowStoreSourceOutput{events: make(chan byte, 8)}
	fixture.cmd = exec.Command(executable, "-test.run=^TestWorkflowHistoryStagingProcessHelper$", "--", workflowHistoryStageSourceArgument)
	fixture.cmd.Stdout, fixture.cmd.Stderr = fixture.output, io.Discard
	fixture.input, err = fixture.cmd.StdinPipe()
	if err != nil {
		t.Fatal("source staging bootstrap pipe unavailable")
	}
	if err := fixture.cmd.Start(); err != nil {
		fixture.cmd = nil
		t.Fatal("source staging child did not start")
	}
	request, err := json.Marshal(map[string]any{"Version": 1, "Root": fixture.root})
	if err != nil || len(request)+1 > 4096 {
		t.Fatal("source staging bootstrap exceeded its bound")
	}
	request = append(request, '\n')
	if n, err := fixture.input.Write(request); err != nil || n != len(request) {
		t.Fatal("source staging bootstrap write failed")
	}
	select {
	case event := <-fixture.output.events:
		if event != 'r' {
			t.Fatal("source staging child emitted an invalid phase")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("source staging child did not reach actual prepared stage")
	}
}

type workflowHistoryStagingFile struct {
	identity os.FileInfo
	bytes    []byte
}

// This is a finite assertion over this fresh synthetic root, never a source of
// production reservation credit or cleanup authority. It excludes child-owned
// descriptors and physical filesystem charge from its claims.
func workflowHistoryStagingFiles(t *testing.T, root string) map[string]workflowHistoryStagingFile {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 32 {
		t.Fatal("source staging root exceeded its fixed fixture bound")
	}
	files := make(map[string]workflowHistoryStagingFile)
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal("source staging object identity unavailable")
		}
		if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 64<<10 {
			t.Fatal("source staging object exceeded the small fixture bound")
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil || len(data) > 64<<10 || int64(len(data)) != info.Size() {
			t.Fatal("source staging object bytes unavailable")
		}
		files[entry.Name()] = workflowHistoryStagingFile{identity: info, bytes: data}
	}
	return files
}

func workflowHistoryStagingSameFiles(t *testing.T, root string, expected map[string]workflowHistoryStagingFile) {
	t.Helper()
	now := workflowHistoryStagingFiles(t, root)
	if len(now) != len(expected) {
		t.Fatal("refused staging attempt allocated or removed a fixture object")
	}
	for name, before := range expected {
		after, exists := now[name]
		if !exists || !os.SameFile(before.identity, after.identity) || !bytes.Equal(before.bytes, after.bytes) {
			t.Fatal("refused staging attempt changed a retained object's identity or bytes")
		}
	}
}

func workflowHistoryStagingReadOriginals(t *testing.T, root string, inventory HistoryInventory, originals map[string][]byte, index []byte) {
	t.Helper()
	reader := workflowHistoryStagingSourceManager(root)
	page, err := reader.HistoryPage(context.Background(), HistoryPageQuery{Limit: 128, Snapshot: inventory.Snapshot})
	if err != nil || page.Inventory.Snapshot != inventory.Snapshot || len(page.Items) != len(originals) {
		t.Fatal("pending stage hid or replaced the old bounded inventory")
	}
	seen := make(map[string]bool)
	for _, row := range page.Items {
		expected, exists := originals[row.Revision]
		if !exists || seen[row.Revision] || !row.RawAvailable {
			t.Fatal("old captured source revision changed")
		}
		seen[row.Revision] = true
		raw, err := reader.ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision)
		if err != nil || !bytes.Equal(raw, expected) {
			t.Fatal("pending stage changed exact old raw evidence")
		}
		detail, err := reader.ReadHistoryRecord(context.Background(), row.RecordRef, row.Revision)
		if err != nil || detail.Record.RecordRef != row.RecordRef || detail.Record.Revision != row.Revision || !detail.RawAvailable {
			t.Fatal("pending stage blocked exact old selected detail")
		}
	}
	current, err := os.ReadFile(filepath.Join(root, historyIndexName))
	if err != nil || !bytes.Equal(current, index) {
		t.Fatal("pending stage changed the original published index")
	}
}

func TestWorkflowHistoryStagingProcessCrashKeepsDurableReservationAndExactReads(t *testing.T) {
	fixture := newWorkflowStoreSourceFixture(t)
	manager := workflowHistoryStagingSourceManager(fixture.root)
	fixture.managers = append(fixture.managers, manager)
	id := strings.Repeat("a", 48)
	canonical := workflowHistoryIntegrationJob(t, id, "retained source-only stage fixture")
	malformed := []byte{0xff, 0xfe, '\n', 0}
	historyUnitRecord(t, manager, id+".json", canonical)
	historyUnitRecord(t, manager, "malformed.json", malformed)
	inventory, err := manager.CaptureHistoryInventory(context.Background())
	if err != nil || inventory.Count != 2 {
		t.Fatal("initial source history capture unavailable")
	}
	index, err := os.ReadFile(filepath.Join(fixture.root, historyIndexName))
	if err != nil || len(index) > 64<<10 {
		t.Fatal("initial source history index unavailable")
	}
	originals := map[string][]byte{
		workflowHistoryIntegrationDigest(canonical): canonical,
		workflowHistoryIntegrationDigest(malformed): malformed,
	}
	workflowHistoryStagingReadOriginals(t, fixture.root, inventory, originals, index)
	workflowHistoryStagingLaunch(t, fixture)
	// The child owns a real active capture/closed prepared stage. A separate
	// Manager must contend on the actual OS lease, while GET evidence reads
	// remain available without inheriting or sharing the child's descriptors.
	other := workflowHistoryStagingSourceManager(fixture.root)
	fixture.managers = append(fixture.managers, other)
	if _, err := other.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrWorkflowBusy) {
		t.Fatal("independent capture entered a real active stage reservation")
	}
	workflowHistoryStagingReadOriginals(t, fixture.root, inventory, originals, index)
	beforeCrash := workflowHistoryStagingFiles(t, fixture.root)
	stages := 0
	for name := range beforeCrash {
		if strings.HasPrefix(name, ".workflow-history-") && strings.HasSuffix(name, ".tmp") {
			stages++
		}
	}
	if stages != 1 {
		t.Fatal("prepared source capture did not reserve exactly one index stage")
	}
	activePath := filepath.Join(fixture.root, workflowActiveLockName)
	activeIdentity, err := os.Lstat(activePath)
	if err != nil {
		t.Fatal("original source active lock identity unavailable")
	}
	if !fixture.finishChild(true) {
		t.Fatal("source staging child crash was not actually joined")
	}
	// This acquisition proves only that OS exclusion is now available. It
	// cannot release durable staging credit or reconstruct original ownership.
	lease, err := openWorkflowStoreLease(activePath)
	if err != nil {
		t.Fatal("actual source child exit did not release its OS lock")
	}
	if lease.Close() != nil {
		fixture.preserve = true
		t.Fatal("parent source lock probe did not close; fixture preserved")
	}
	activeAfter, err := os.Lstat(activePath)
	if err != nil || !os.SameFile(activeIdentity, activeAfter) {
		t.Fatal("source crash recovery replaced or deleted the persistent lock file")
	}
	workflowHistoryStagingSameFiles(t, fixture.root, beforeCrash)
	for attempt := 0; attempt < 6; attempt++ {
		fresh := workflowHistoryStagingSourceManager(fixture.root)
		fixture.managers = append(fixture.managers, fresh)
		if _, err := fresh.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) || strings.Contains(err.Error(), fixture.root) {
			t.Fatal("free OS lock or fresh Manager discharged unknown staging ownership")
		}
		workflowHistoryStagingSameFiles(t, fixture.root, beforeCrash)
		workflowHistoryStagingReadOriginals(t, fixture.root, inventory, originals, index)
	}
	if original, err := os.ReadFile(filepath.Join(manager.root, id+".json")); err != nil || !bytes.Equal(original, canonical) {
		t.Fatal("durable staging refusal changed the original source job")
	}
	if original, err := os.ReadFile(filepath.Join(manager.root, "malformed.json")); err != nil || !bytes.Equal(original, malformed) {
		t.Fatal("durable staging refusal changed malformed source evidence")
	}
}
