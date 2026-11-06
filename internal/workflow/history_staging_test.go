package workflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/Yunushan/accessweaver/internal/privatefile"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func historyStagingSeed(t *testing.T, m *Manager) (HistoryInventory, HistoryRecordSummary, []byte) {
	t.Helper()
	id := strings.Repeat("a", 48)
	body := historyUnitJob(t, id)
	historyUnitRecord(t, m, id+".json", body)
	inventory := historyUnitCapture(t, m)
	rows := historyUnitAll(t, m, inventory.Snapshot)
	if len(rows) != 1 {
		t.Fatal("staging seed row missing")
	}
	return inventory, rows[0], body
}
func historyStagingNames(t *testing.T, root string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string][]byte{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = data
	}
	return result
}
func historyStagingSame(t *testing.T, root string, want map[string][]byte) {
	t.Helper()
	got := historyStagingNames(t, root)
	if len(got) != len(want) {
		t.Fatal("refused staging added another retained object")
	}
	for name, data := range want {
		if !bytes.Equal(got[name], data) {
			t.Fatal("refused staging changed retained evidence")
		}
	}
}
func historyStagingReadOld(t *testing.T, m *Manager, inventory HistoryInventory, row HistoryRecordSummary, body []byte) {
	t.Helper()
	if _, err := m.HistoryPage(context.Background(), HistoryPageQuery{Snapshot: inventory.Snapshot}); err != nil {
		t.Fatal("staging fault blocked existing page")
	}
	raw, err := m.ReadHistoryRecordRaw(context.Background(), row.RecordRef, row.Revision)
	if err != nil || !bytes.Equal(raw, body) {
		t.Fatal("staging fault changed exact raw evidence")
	}
}
func TestWorkflowHistoryStagingPhysicalFaultsDoNotAccumulate(t *testing.T) {
	for _, phase := range []string{"write", "sync", "close", "prepared", "publish", "control"} {
		t.Run(phase, func(t *testing.T) {
			m := New(t.TempDir())
			inventory, row, body := historyStagingSeed(t, m)
			oldIndex, err := os.ReadFile(filepath.Join(m.storeRoot, historyIndexName))
			if err != nil {
				t.Fatal(err)
			}
			cause := errors.New("PRIVATE_STAGE_CAUSE")
			hooks := &historyStagingHooks{}
			switch phase {
			case "write":
				hooks.afterWrite = func(string) error { return cause }
			case "sync":
				hooks.afterSync = func(string) error { return cause }
			case "close":
				hooks.afterClose = func(string) error { return cause }
			case "prepared":
				hooks.afterPrepared = func() error { return cause }
			case "publish":
				hooks.beforePublish = func(string, string) error { return cause }
			case "control":
				hooks.afterControlWrite = func(string) error { return cause }
			}
			m.historyStagingHooks = hooks
			_, err = m.CaptureHistoryInventory(context.Background())
			if !errors.Is(err, ErrHistoryStagingPending) || !errors.Is(err, cause) || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("physical stage fault lost bounded pending category/private cause")
			}
			stages := 0
			for name := range historyStagingNames(t, m.storeRoot) {
				if strings.HasPrefix(name, historyStageDataPrefix) && strings.HasSuffix(name, ".tmp") {
					stages++
				}
			}
			if stages != 1 {
				t.Fatal("fault did not retain exactly one bounded data/control stage")
			}
			want := historyStagingNames(t, m.storeRoot)
			for n := 0; n < 4; n++ {
				candidate := m
				if n > 0 {
					candidate = New(m.storeRoot)
				}
				if _, err = candidate.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
					t.Fatal("retained uncertain stage admitted another capture")
				}
				historyStagingSame(t, m.storeRoot, want)
				historyStagingReadOld(t, candidate, inventory, row, body)
			}
			after, err := os.ReadFile(filepath.Join(m.storeRoot, historyIndexName))
			if err != nil || !bytes.Equal(oldIndex, after) {
				t.Fatal("pre-publication fault replaced old inventory")
			}
		})
	}
}
func TestWorkflowHistoryStagingCountBeforePhysicalWrite(t *testing.T) {
	if historyStageMaxBytes != 134221824 || 2*historyStageMaxBytes+2*historyStageControlMax != 268451840 {
		t.Fatal("staging component bounds changed")
	}
	dir := t.TempDir()
	file, err := privatefile.Create(filepath.Join(dir, "owned"))
	if err != nil {
		t.Fatal(err)
	}
	reservation := &historyStageReservation{manager: New(dir)}
	writer := &historyStageFile{file: file, reservation: reservation, limit: 8, bodyKnown: true, body: sha256.New()}
	if n, err := writer.Write([]byte("12345678")); err != nil || n != 8 {
		t.Fatal("exact byte cap refused")
	}
	if n, err := writer.Write([]byte("9")); !errors.Is(err, ErrHistoryCapacity) || n != 0 {
		t.Fatal("over-cap byte reached physical write")
	}
	if n, err := writer.WriteAt([]byte("x"), 8); !errors.Is(err, ErrHistoryCapacity) || n != 0 {
		t.Fatal("over-cap offset reached physical write")
	}
	if _, err := writer.WriteAt([]byte("x"), math.MaxInt64); !errors.Is(err, ErrHistoryCapacity) {
		t.Fatal("write arithmetic overflow admitted")
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 8 {
		t.Fatal("refused byte extended the owned file")
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil || string(data) != "12345678" {
		t.Fatal("refused writes changed prior bytes")
	}
}
func TestWorkflowHistoryStagingKnownCancellationReturnsOnlyOwnedSlot(t *testing.T) {
	m := New(t.TempDir())
	inventory, row, body := historyStagingSeed(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.historyStagingHooks = &historyStagingHooks{afterWrite: func(string) error { cancel(); return nil }}
	if _, err := m.CaptureHistoryInventory(ctx); !errors.Is(err, context.Canceled) || errors.Is(err, ErrHistoryStagingPending) {
		t.Fatalf("known cancellation did not finish owned removal: %v", err)
	}
	control, _, err := readHistoryStageControl(context.Background(), filepath.Join(m.storeRoot, historyStageReservationName))
	if err != nil || control.Phase != "discarded" || !control.DataWriterClosed || !control.RemovalObserved || control.PublicationObserved {
		t.Fatal("discard claimed phase without actual closed/removed observations")
	}
	for name := range historyStagingNames(t, m.storeRoot) {
		if strings.HasPrefix(name, historyStageDataPrefix) && strings.HasSuffix(name, ".tmp") {
			t.Fatal("known cancellation retained reusable derived stage")
		}
	}
	historyStagingReadOld(t, m, inventory, row, body)
	fresh := New(m.storeRoot)
	if _, err = fresh.CaptureHistoryInventory(context.Background()); err != nil {
		t.Fatal("known source-owned cleanup failed to return staging slot")
	}
}
func TestWorkflowHistoryStagingIdenticalReplacementAndChangedBytesStayProtected(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-bytes", true: "same-bytes-new-object"}[replacement], func(t *testing.T) {
			m := New(t.TempDir())
			inventory, row, body := historyStagingSeed(t, m)
			var stage string
			m.historyStagingHooks = &historyStagingHooks{afterClose: func(path string) error {
				stage = path
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if replacement {
					if err = os.Rename(path, path+".preserved"); err != nil {
						return err
					}
				} else {
					data[0] ^= 1
				}
				return os.WriteFile(path, data, 0600)
			}}
			if _, err := m.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
				t.Fatal("replacement supplied positive closed-stage observation")
			}
			if _, err := os.Lstat(stage); err != nil {
				t.Fatal("unknown replacement was removed")
			}
			want := historyStagingNames(t, m.storeRoot)
			fresh := New(m.storeRoot)
			if _, err := fresh.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
				t.Fatal("unknown replacement admitted staging")
			}
			historyStagingSame(t, m.storeRoot, want)
			historyStagingReadOld(t, fresh, inventory, row, body)
		})
	}
}
func TestWorkflowHistoryStagingControlCodecRejectsAmbiguityAndPhaseOnlyClaims(t *testing.T) {
	for _, kind := range []string{"duplicate", "case-alias", "unknown", "noncanonical", "phase-only", "published-small", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			m := New(t.TempDir())
			inventory, row, body := historyStagingSeed(t, m)
			path := filepath.Join(m.storeRoot, historyStageReservationName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "duplicate":
				data = append([]byte(`{"phase":"published",`), data[1:]...)
			case "case-alias":
				data = bytes.Replace(data, []byte(`"phase"`), []byte(`"Phase"`), 1)
			case "unknown":
				data = append([]byte(`{"future":true,`), data[1:]...)
			case "noncanonical":
				data = append(data, '\n')
			case "phase-only":
				data = bytes.Replace(data, []byte(`"dataWriterClosed":true`), []byte(`"dataWriterClosed":false`), 1)
			case "published-small":
				var control historyStageControl
				if json.Unmarshal(data, &control) != nil {
					t.Fatal("control fixture decode failed")
				}
				control.Stage.Size = 1
				control.Index.Size = 1
				data, err = json.Marshal(control)
				if err != nil {
					t.Fatal(err)
				}
			case "oversized":
				data = bytes.Repeat([]byte(" "), historyStageControlMax+1)
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readHistoryStageControl(context.Background(), path); err == nil {
				t.Fatal("invalid canonical/semantic control shape accepted")
			}
			before := historyStagingNames(t, m.storeRoot)
			if _, err = m.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
				t.Fatal("untrusted control state admitted staging")
			}
			historyStagingSame(t, m.storeRoot, before)
			historyStagingReadOld(t, m, inventory, row, body)
		})
	}
}
func TestWorkflowHistoryStagingPublicationCompletionFaultPreservesReadableIndex(t *testing.T) {
	m := New(t.TempDir())
	_, _, body := historyStagingSeed(t, m)
	count := 0
	cause := errors.New("PRIVATE_CONTROL_COMMIT_FAILURE")
	m.historyStagingHooks = &historyStagingHooks{afterControlWrite: func(string) error {
		count++
		if count == 3 {
			return cause
		}
		return nil
	}}
	if _, err := m.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) || !errors.Is(err, cause) {
		t.Fatal("post-promotion control fault became successful capture")
	}
	page, err := m.HistoryPage(context.Background(), HistoryPageQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("confirmed promoted index became unreadable")
	}
	raw, err := m.ReadHistoryRecordRaw(context.Background(), page.Items[0].RecordRef, page.Items[0].Revision)
	if err != nil || !bytes.Equal(raw, body) {
		t.Fatal("post-promotion fault changed source evidence")
	}
	before := historyStagingNames(t, m.storeRoot)
	if _, err = New(m.storeRoot).CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
		t.Fatal("unknown control completion was automatically cleared")
	}
	historyStagingSame(t, m.storeRoot, before)
}
func TestWorkflowHistoryStagingCallerCancellationCannotAbandonOwnedClose(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	m := f.manager
	historyStagingSeed(t, m)
	entered, release := f.barrier()
	var once sync.Once
	m.historyStagingHooks = &historyStagingHooks{afterClose: func(string) error { once.Do(func() { close(entered); release() }); return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	f.starts = append(f.starts, done)
	result := make(chan error, 1)
	go func() { defer close(done); _, err := m.CaptureHistoryInventory(ctx); result <- err }()
	workflowShutdownAwait(t, entered, "capture Close did not enter")
	cancel()
	select {
	case <-done:
		t.Fatal("caller cancellation abandoned accepted Close")
	case <-time.After(20 * time.Millisecond):
	}
	snapshotDone := make(chan struct{})
	go func() { m.Snapshot(); m.Cancel(); close(snapshotDone) }()
	workflowShutdownAwait(t, snapshotDone, "controls held status mutex during Close")
	if _, err := New(m.storeRoot).CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrWorkflowBusy) {
		t.Fatal("live capture released active reservation early")
	}
	f.unblockAll()
	workflowShutdownAwait(t, done, "actual Close did not drain")
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation cause disappeared")
	}
}

func TestWorkflowHistoryStagingControlContentChangeCannotAuthorizeReplacement(t *testing.T) {
	m := New(t.TempDir())
	inventory, row, body := historyStagingSeed(t, m)
	target := filepath.Join(m.storeRoot, historyStageReservationName)
	var changed []byte
	m.historyStagingHooks = &historyStagingHooks{afterControlWrite: func(string) error {
		data, err := os.ReadFile(target)
		if err != nil {
			return err
		}
		var control historyStageControl
		if err = json.Unmarshal(data, &control); err != nil {
			return err
		}
		if control.Snapshot[0] == '0' {
			control.Snapshot = "1" + control.Snapshot[1:]
		} else {
			control.Snapshot = "0" + control.Snapshot[1:]
		}
		control.StageLeaf = historyStageDataPrefix + control.Snapshot + ".tmp"
		changed, err = json.Marshal(control)
		if err != nil {
			return err
		}
		if len(changed) != len(data) {
			return errors.New("fixture control length changed")
		}
		return os.WriteFile(target, changed, 0600)
	}}
	if _, err := m.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
		t.Fatal("changed control bytes were overwritten using stale interpretation")
	}
	now, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(now, changed) {
		t.Fatal("unknown changed control evidence was replaced")
	}
	historyStagingReadOld(t, m, inventory, row, body)
}

func TestWorkflowHistoryStagingNamedSymlinkCannotBecomePublishedIndex(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink source fixture does not request Windows link privileges")
	}
	m := New(t.TempDir())
	inventory, row, body := historyStagingSeed(t, m)
	transactions := 0
	var stage string
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		if filepath.Base(path) == workflowTransactionLockName {
			transactions++
			if transactions == 3 {
				matches, err := filepath.Glob(filepath.Join(m.storeRoot, historyStageDataPrefix+"*.tmp"))
				if err != nil || len(matches) != 1 {
					return nil, errors.New("source stage fixture unavailable")
				}
				stage = matches[0]
				preserved := stage + ".preserved"
				if err = os.Rename(stage, preserved); err != nil {
					return nil, err
				}
				if err = os.Symlink(preserved, stage); err != nil {
					return nil, err
				}
			}
		}
		return openWorkflowStoreLease(path)
	}
	if _, err := m.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
		t.Fatal("named symlink was promoted using followed known-file identity")
	}
	info, err := os.Lstat(stage)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("unknown substituted link was removed or replaced")
	}
	historyStagingReadOld(t, m, inventory, row, body)
}

func TestWorkflowHistoryStagingFailedPhysicalEpochBootstrapCannotAccumulate(t *testing.T) {
	m := New(t.TempDir())
	id := strings.Repeat("a", 48)
	body := historyUnitJob(t, id)
	historyUnitRecord(t, m, id+".json", body)
	cause := errors.New("PRIVATE_EPOCH_PUBLICATION_FAILURE")
	calls := 0
	m.historyStagingHooks = &historyStagingHooks{beforeEpochPublish: func(stage, target string) error {
		calls++
		data, err := os.ReadFile(stage)
		if err != nil || len(data) != 49 || filepath.Base(target) != historyRevisionName {
			return errors.New("bootstrap physical stage invalid")
		}
		return cause
	}}
	if _, err := m.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) || !errors.Is(err, cause) {
		t.Fatal("actual failed epoch stage was not retained as pending")
	}
	if calls != 1 {
		t.Fatal("physical epoch fault seam did not execute once")
	}
	before := historyStagingNames(t, m.storeRoot)
	stages := 0
	for name, data := range before {
		if strings.HasPrefix(name, ".workflow-data-") && strings.HasSuffix(name, ".tmp") {
			stages++
			if len(data) != 49 {
				t.Fatal("epoch bootstrap exceeded its distinct49byte bound")
			}
		}
	}
	if stages != 1 {
		t.Fatal("physical failed bootstrap stage missing")
	}
	for n := 0; n < 4; n++ {
		if _, err := New(m.storeRoot).CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
			t.Fatal("failed epoch bootstrap admitted another write")
		}
		historyStagingSame(t, m.storeRoot, before)
	}
	data, err := os.ReadFile(filepath.Join(m.root, id+".json"))
	if err != nil || !bytes.Equal(data, body) {
		t.Fatal("bootstrap refusal changed original evidence")
	}
}
func TestWorkflowHistoryStagingPostPromotionMutationNeverGetsPublishedCredit(t *testing.T) {
	m := New(t.TempDir())
	historyStagingSeed(t, m)
	transactions := 0
	var changed []byte
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		if filepath.Base(path) == workflowTransactionLockName {
			transactions++
			if transactions == 3 {
				matches, err := filepath.Glob(filepath.Join(m.storeRoot, historyStageDataPrefix+"*.tmp"))
				if err != nil || len(matches) != 1 {
					return nil, errors.New("mutation fixture stage missing")
				}
				before, err := os.Stat(matches[0])
				if err != nil {
					return nil, err
				}
				data, err := os.ReadFile(matches[0])
				if err != nil {
					return nil, err
				}
				data[len(data)-1] ^= 1
				changed = append([]byte(nil), data...)
				if err = os.WriteFile(matches[0], data, 0600); err != nil {
					return nil, err
				}
				// Deliberately restore the old stamp: only the required full
				// post-promotion content check can detect this mutation.
				if err = os.Chtimes(matches[0], before.ModTime(), before.ModTime()); err != nil {
					return nil, err
				}
			}
		}
		return openWorkflowStoreLease(path)
	}
	if _, err := m.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
		t.Fatal("changed promoted bytes received successful slot credit")
	}
	data, err := os.ReadFile(filepath.Join(m.storeRoot, historyIndexName))
	if err != nil || !bytes.Equal(data, changed) {
		t.Fatal("changed promoted evidence was rolled back or removed")
	}
	control, _, err := readHistoryStageControl(context.Background(), filepath.Join(m.storeRoot, historyStageReservationName))
	if err != nil || control.Phase != "prepared" || control.PublicationObserved {
		t.Fatal("changed content acquired a published completion certificate")
	}
	before := historyStagingNames(t, m.storeRoot)
	if _, err = New(m.storeRoot).CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
		t.Fatal("unknown promoted evidence was automatically cleared")
	}
	historyStagingSame(t, m.storeRoot, before)
}

func TestWorkflowHistoryStagingFinalTransactionMutationLosesSlotCredit(t *testing.T) {
	m := New(t.TempDir())
	historyStagingSeed(t, m)
	transactions := 0
	var changed []byte
	m.openStoreLease = func(path string) (workflowStoreLease, error) {
		if filepath.Base(path) == workflowTransactionLockName {
			transactions++
			if transactions == 4 {
				target := filepath.Join(m.storeRoot, historyIndexName)
				data, err := os.ReadFile(target)
				if err != nil {
					return nil, err
				}
				info, err := os.Stat(target)
				if err != nil {
					return nil, err
				}
				data[len(data)-1] ^= 1
				changed = append([]byte(nil), data...)
				if err = os.WriteFile(target, data, 0600); err != nil {
					return nil, err
				}
				stamp := info.ModTime().Add(2 * time.Second)
				if err = os.Chtimes(target, stamp, stamp); err != nil {
					return nil, err
				}
			}
		}
		return openWorkflowStoreLease(path)
	}
	if _, err := m.CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
		t.Fatal("same-ID/size final transaction mutation received stale snapshot credit")
	}
	data, err := os.ReadFile(filepath.Join(m.storeRoot, historyIndexName))
	if err != nil || !bytes.Equal(data, changed) {
		t.Fatal("changed final-boundary evidence was repaired or deleted")
	}
	control, _, err := readHistoryStageControl(context.Background(), filepath.Join(m.storeRoot, historyStageReservationName))
	if err != nil || control.Phase != "prepared" || control.PublicationObserved {
		t.Fatal("late changed snapshot acquired a published certificate")
	}
	if _, err = New(m.storeRoot).CaptureHistoryInventory(context.Background()); !errors.Is(err, ErrHistoryStagingPending) {
		t.Fatal("unknown late mutation supplied release proof")
	}
}
