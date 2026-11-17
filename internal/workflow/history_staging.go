package workflow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Yunushan/accessweaver/internal/privatefile"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var ErrHistoryStagingPending = errors.New("workflow history staging requires explicit review; all evidence retained")
var errHistoryCaptureClosing = errors.New("workflow manager is shutting down")

const historyStageReservationName = ".workflow-history.stage-reservation"
const historyStageControlPrefix = ".workflow-history-reservation-"
const historyStageDataPrefix = ".workflow-history-"
const historyStageControlMax = 4096
const historyStageMaxBytes = int64(historyHeaderBytes) + int64(historyMaxEntries)*historySlotBytes

// Hooks observe/fault physical operations AFTER they actually occur. They do
// not replace writes or issue positive closure facts, and have no public selector.
type historyStagingHooks struct {
	beforeEpochPublish func(string, string) error
	afterWrite         func(string) error
	afterSync          func(string) error
	afterClose         func(string) error
	afterControlWrite  func(string) error
	afterPrepared      func() error
	beforePublish      func(string, string) error
}

// Identity, length and UTC modification stamp bridge an observed content hash
// across short transactions. These detect conflicts, not atomic immutability
// against arbitrary same-user writers that restore timestamps, or bad clocks.
// Authority remains actual owned writer Sync/Close plus the active lease.
type historyStageBinding struct {
	ModifiedAt time.Time `json:"modifiedAt"`
	Identity   string    `json:"identity"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
}
type historyStageControl struct {
	Version             int                  `json:"version"`
	Snapshot            string               `json:"snapshot"`
	StoreRevision       string               `json:"storeRevision"`
	Root                string               `json:"root"`
	StageLeaf           string               `json:"stageLeaf"`
	ReservedBytes       int64                `json:"reservedBytes"`
	Phase               string               `json:"phase"`
	DataWriterClosed    bool                 `json:"dataWriterClosed"`
	DataSyncObserved    bool                 `json:"dataSyncObserved"`
	PublicationObserved bool                 `json:"publicationObserved"`
	RemovalObserved     bool                 `json:"removalObserved"`
	Stage               *historyStageBinding `json:"stage,omitempty"`
	Index               *historyStageBinding `json:"index,omitempty"`
}
type historyStageReservation struct {
	manager              *Manager
	control              historyStageControl
	controlBinding       *historyStageBinding
	priorIndex           *historyStageBinding
	file                 *historyStageFile
	finished             bool
	uncertain            bool
	publicationAttempted bool
}
type historyStageFile struct {
	file              *os.File
	reservation       *historyStageReservation
	limit             int64
	offset, size      int64
	identity          string
	initial           os.FileInfo
	header            []byte
	body              hash.Hash
	bodyKnown         bool
	closed, uncertain bool
	synced            bool
}

func historyStagePending(cause error) error                  { return historyError(ErrHistoryStagingPending, cause) }
func sameHistoryStageBinding(a, b *historyStageBinding) bool { return a != nil && b != nil && *a == *b }
func validHistoryStageBinding(b *historyStageBinding) bool {
	return b != nil && b.Identity != "" && len(b.Identity) <= 128 && b.Size >= 0 && b.Size <= historyStageMaxBytes && historyHex(b.SHA256, 64) && !b.ModifiedAt.IsZero() && b.ModifiedAt.Location() == time.UTC
}

// Complete bounded reads are outside short transaction leases. A native ID is
// only a replacement detector, never evidence that an old writer closed.
func inspectHistoryStage(path string, limit int64, expectedHeader, expectedBody []byte) (binding *historyStageBinding, failure error) {
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !named.Mode().IsRegular() || named.Size() < 0 || named.Size() > limit {
		return nil, ErrHistoryStagingPending
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			binding = nil
			failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, err))
		}
	}()
	before, err := f.Stat()
	if err != nil || !os.SameFile(named, before) {
		return nil, errors.Join(ErrHistoryStagingPending, err)
	}
	identity, links, err := reconciliationFileIdentity(f)
	if err != nil || links != 1 {
		return nil, errors.Join(ErrHistoryStagingPending, err)
	}
	all, body := sha256.New(), sha256.New()
	var count int64
	if expectedHeader != nil {
		header := make([]byte, len(expectedHeader))
		if _, err = io.ReadFull(f, header); err != nil || !bytes.Equal(header, expectedHeader) {
			return nil, errors.Join(ErrHistoryStagingPending, err)
		}
		all.Write(header)
		count = int64(len(header))
	}
	n, err := io.CopyBuffer(io.MultiWriter(all, body), io.LimitReader(f, limit-count+1), make([]byte, 32<<10))
	if err != nil || n+count > limit {
		return nil, errors.Join(ErrHistoryStagingPending, err)
	}
	count += n
	if expectedBody != nil && !bytes.Equal(body.Sum(nil), expectedBody) {
		return nil, ErrHistoryStagingPending
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(before, after) || !os.SameFile(after, current) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || after.Size() != count {
		return nil, errors.Join(ErrHistoryStagingPending, err)
	}
	return &historyStageBinding{Identity: identity, Size: count, SHA256: hex.EncodeToString(all.Sum(nil)), ModifiedAt: after.ModTime().UTC()}, nil
}
func quickHistoryStageBinding(path string, want *historyStageBinding) error {
	return quickHistoryStageBindingLinks(path, want, 1)
}
func quickHistoryStageBindingLinks(path string, want *historyStageBinding, wantLinks uint64) (failure error) {
	named, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !named.Mode().IsRegular() {
		return ErrHistoryStagingPending
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, err))
		}
	}()
	info, statErr := f.Stat()
	identity, links, idErr := reconciliationFileIdentity(f)
	if statErr != nil || idErr != nil || !info.Mode().IsRegular() || !os.SameFile(named, info) || info.Size() != want.Size || !info.ModTime().Equal(want.ModifiedAt) || identity != want.Identity || links != wantLinks {
		return errors.Join(ErrHistoryStagingPending, statErr, idErr)
	}
	after, statErr := f.Stat()
	current, nameErr := os.Lstat(path)
	afterIdentity, afterLinks, identityErr := reconciliationFileIdentity(f)
	if statErr != nil || nameErr != nil || identityErr != nil || !current.Mode().IsRegular() || !os.SameFile(info, after) || !os.SameFile(after, current) || after.Size() != want.Size || !after.ModTime().Equal(want.ModifiedAt) || afterIdentity != want.Identity || afterLinks != wantLinks {
		return errors.Join(ErrHistoryStagingPending, statErr, nameErr, identityErr)
	}
	return nil
}

// Decode and native binding share one opened, bounded read. Never bind an
// interpretation of A to a later independent observation of changed bytes B.
func readHistoryStageControlBound(path string) (data []byte, binding *historyStageBinding, failure error) {
	named, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !named.Mode().IsRegular() || named.Size() < 0 || named.Size() > historyStageControlMax {
		return nil, nil, ErrHistoryStagingPending
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			data = nil
			binding = nil
			failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, err))
		}
	}()
	before, err := file.Stat()
	if err != nil || !os.SameFile(named, before) {
		return nil, nil, errors.Join(ErrHistoryStagingPending, err)
	}
	identity, links, err := reconciliationFileIdentity(file)
	if err != nil || links != 1 {
		return nil, nil, errors.Join(ErrHistoryStagingPending, err)
	}
	data, err = io.ReadAll(io.LimitReader(file, historyStageControlMax+1))
	if err != nil || len(data) > historyStageControlMax {
		return nil, nil, errors.Join(ErrHistoryStagingPending, err)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(before, after) || !os.SameFile(after, current) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || after.Size() != int64(len(data)) {
		return nil, nil, errors.Join(ErrHistoryStagingPending, err)
	}
	return data, &historyStageBinding{Identity: identity, Size: int64(len(data)), SHA256: workflowLifecycleHash(data), ModifiedAt: after.ModTime().UTC()}, nil
}
func readHistoryStageControl(ctx context.Context, path string) (control historyStageControl, binding *historyStageBinding, err error) {
	if err = ctx.Err(); err != nil {
		return control, nil, err
	}
	data, binding, err := readHistoryStageControlBound(path)
	if err != nil {
		return control, nil, err
	}
	if err = decodeWorkflowLifecycle(data, &control); err != nil {
		return control, nil, err
	}
	if control.Version != 1 || !historyHex(control.Snapshot, 48) || !historyHex(control.StoreRevision, 48) || !historyHex(control.Root, 64) || control.StageLeaf != historyStageDataPrefix+control.Snapshot+".tmp" || control.ReservedBytes != historyStageMaxBytes {
		return control, nil, ErrHistoryStagingPending
	}
	switch control.Phase {
	case "reserved":
		if control.Stage != nil || control.Index != nil || control.DataWriterClosed || control.DataSyncObserved || control.PublicationObserved || control.RemovalObserved {
			return control, nil, ErrHistoryStagingPending
		}
	case "prepared":
		if !validHistoryStageBinding(control.Stage) || control.Stage.Size < historyHeaderBytes || control.Index != nil || !control.DataWriterClosed || !control.DataSyncObserved || control.PublicationObserved || control.RemovalObserved {
			return control, nil, ErrHistoryStagingPending
		}
	case "published":
		if !validHistoryStageBinding(control.Stage) || control.Stage.Size < historyHeaderBytes || !sameHistoryStageBinding(control.Stage, control.Index) || !control.DataWriterClosed || !control.DataSyncObserved || !control.PublicationObserved || control.RemovalObserved {
			return control, nil, ErrHistoryStagingPending
		}
	case "discarded":
		if control.Stage == nil || !validHistoryStageBinding(control.Stage) || control.Index != nil || !control.DataWriterClosed || !control.RemovalObserved || control.PublicationObserved {
			return control, nil, ErrHistoryStagingPending
		}
	default:
		return control, nil, ErrHistoryStagingPending
	}
	if err = ctx.Err(); err != nil {
		return control, nil, err
	}
	return control, binding, nil
}
func (m *Manager) historyStageScan(ctx context.Context) error {
	f, err := os.Open(m.storeRoot)
	if err != nil {
		return err
	}
	entries, readErr := f.ReadDir(65537)
	closeErr := f.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > 65536 {
		return errors.Join(ErrHistoryStagingPending, readErr, workflowFailure(ErrWorkflowCleanup, closeErr))
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".tmp") && (strings.HasPrefix(name, historyStageDataPrefix) || strings.HasPrefix(name, historyStageControlPrefix) || strings.HasPrefix(name, ".workflow-data-")) {
			return ErrHistoryStagingPending
		}
	}
	return nil
}

// Caller holds active->transaction. The complete old index was inspected before
// this short lease; the lease performs only bounded names/control and identity IO.
func (m *Manager) reserveHistoryStage(ctx context.Context, snapshot, revision string, prior *historyStageBinding) (*historyStageReservation, error) {
	m.mu.Lock()
	closing, storeFailure := m.closing, m.storeFailure
	m.mu.Unlock()
	if storeFailure != nil {
		return nil, storeFailure
	}
	if closing {
		return nil, historyError(ErrHistoryUnavailable, errHistoryCaptureClosing)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := m.historyStageScan(ctx); err != nil {
		return nil, historyStagePending(err)
	}
	root, err := m.reconciliationRoot()
	if err != nil {
		return nil, historyStagePending(err)
	}
	old, binding, err := readHistoryStageControl(ctx, filepath.Join(m.storeRoot, historyStageReservationName))
	if err == nil {
		if old.Root != root || (old.Phase != "published" && old.Phase != "discarded") {
			return nil, ErrHistoryStagingPending
		}
		if old.Phase == "published" && !sameHistoryStageBinding(old.Index, prior) {
			return nil, ErrHistoryStagingPending
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, historyStagePending(err)
	}
	if prior != nil {
		if err = quickHistoryStageBinding(filepath.Join(m.storeRoot, historyIndexName), prior); err != nil {
			return nil, historyStagePending(err)
		}
	}
	r := &historyStageReservation{manager: m, control: historyStageControl{Version: 1, Snapshot: snapshot, StoreRevision: revision, Root: root, StageLeaf: historyStageDataPrefix + snapshot + ".tmp", ReservedBytes: historyStageMaxBytes, Phase: "reserved"}, controlBinding: binding, priorIndex: prior}
	if err = r.writeControl(); err != nil {
		return nil, historyStagePending(err)
	}
	return r, nil
}
func (r *historyStageReservation) checkRoot() error {
	root, err := r.manager.reconciliationRoot()
	if err != nil || root != r.control.Root {
		return historyStagePending(err)
	}
	return nil
}
func (r *historyStageReservation) writeControl() (failure error) {
	if err := r.checkRoot(); err != nil {
		return err
	}
	b, err := json.Marshal(r.control)
	if err != nil || len(b) > historyStageControlMax {
		return errors.Join(ErrHistoryStagingPending, err)
	}
	m := r.manager
	path := filepath.Join(m.storeRoot, historyStageReservationName)
	if r.controlBinding != nil {
		current, checkErr := inspectHistoryStage(path, historyStageControlMax, nil, nil)
		if checkErr != nil || !sameHistoryStageBinding(current, r.controlBinding) {
			return errors.Join(ErrHistoryStagingPending, checkErr)
		}
	} else if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrHistoryStagingPending, err)
	}
	f, err := privateHistoryStageControlFile(m.storeRoot)
	if err != nil {
		return err
	}
	stage := f.Name()
	initialIdentity, initialLinks, initialErr := reconciliationFileIdentity(f)
	closed := false
	defer func() {
		if !closed {
			failure = errors.Join(failure, workflowFailure(ErrWorkflowCleanup, f.Close()))
		}
	}()
	if initialErr != nil || initialLinks != 1 {
		return errors.Join(ErrHistoryStagingPending, initialErr)
	}
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	if hooks := m.historyStagingHooks; hooks != nil && hooks.afterControlWrite != nil {
		if err = hooks.afterControlWrite(stage); err != nil {
			return err
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	closed = true
	if err = f.Close(); err != nil {
		return workflowFailure(ErrWorkflowCleanup, err)
	}
	observed, err := inspectHistoryStage(stage, historyStageControlMax, nil, nil)
	if err != nil || observed.SHA256 != workflowLifecycleHash(b) || observed.Identity != initialIdentity {
		return errors.Join(ErrHistoryStagingPending, err)
	}
	if r.controlBinding == nil {
		if err = os.Link(stage, path); err != nil {
			return err
		}
		if err = quickHistoryStageBindingLinks(stage, observed, 2); err != nil {
			return err
		}
		if err = quickHistoryStageBindingLinks(path, observed, 2); err != nil {
			return err
		}
		if err = os.Remove(stage); err != nil {
			return err
		}
	} else {
		current, checkErr := inspectHistoryStage(path, historyStageControlMax, nil, nil)
		if checkErr != nil || !sameHistoryStageBinding(current, r.controlBinding) {
			return errors.Join(ErrHistoryStagingPending, checkErr)
		}
		if err = replaceHistoryIndex(stage, path); err != nil {
			return err
		}
	}
	if err = quickHistoryStageBinding(path, observed); err != nil {
		return err
	}
	r.controlBinding = observed
	return nil
}
func privateHistoryStageControlFile(root string) (*os.File, error) {
	return privatefile.CreateTemp(root, historyStageControlPrefix+"*.tmp")
}
func (r *historyStageReservation) Create() (*historyStageFile, error) {
	if err := r.checkRoot(); err != nil {
		return nil, err
	}
	f, err := privatefile.Create(filepath.Join(r.manager.storeRoot, r.control.StageLeaf))
	if err != nil {
		return nil, historyStagePending(err)
	}
	info, statErr := f.Stat()
	identity, links, idErr := reconciliationFileIdentity(f)
	if statErr != nil || idErr != nil || !info.Mode().IsRegular() || info.Size() != 0 || links != 1 {
		return nil, historyStagePending(errors.Join(statErr, idErr, workflowFailure(ErrWorkflowCleanup, f.Close())))
	}
	r.file = &historyStageFile{file: f, reservation: r, limit: historyStageMaxBytes, identity: identity, initial: info, body: sha256.New(), bodyKnown: true}
	return r.file, nil
}
func historyStageWriteEnd(offset int64, count int, limit int64) (int64, error) {
	if offset < 0 || count < 0 || offset > limit || int64(count) > limit-offset {
		return 0, ErrHistoryCapacity
	}
	return offset + int64(count), nil
}
func (f *historyStageFile) Write(b []byte) (int, error) {
	f.synced = false
	end, err := historyStageWriteEnd(f.offset, len(b), f.limit)
	if err != nil {
		return 0, err
	}
	n, err := f.file.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		f.uncertain = true
		return n, err
	}
	start := f.offset
	f.offset = end
	if end > f.size {
		f.size = end
	}
	if start == 0 && len(b) >= historyHeaderBytes {
		f.header = append([]byte(nil), b[:historyHeaderBytes]...)
	}
	if start < int64(historyHeaderBytes) {
		skip := int64(historyHeaderBytes) - start
		if skip < int64(len(b)) {
			f.body.Write(b[skip:])
		}
	} else {
		f.body.Write(b)
	}
	if hooks := f.reservation.manager.historyStagingHooks; hooks != nil && hooks.afterWrite != nil {
		err = hooks.afterWrite(f.file.Name())
		if err != nil {
			f.uncertain = true
		}
	}
	return n, err
}
func (f *historyStageFile) WriteAt(b []byte, offset int64) (int, error) {
	f.synced = false
	end, err := historyStageWriteEnd(offset, len(b), f.limit)
	if err != nil {
		return 0, err
	}
	n, err := f.file.WriteAt(b, offset)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		f.uncertain = true
		return n, err
	}
	if end > f.size {
		f.size = end
	}
	if offset == 0 && len(b) == historyHeaderBytes {
		f.header = append([]byte(nil), b...)
	} else {
		f.bodyKnown = false
	}
	if hooks := f.reservation.manager.historyStagingHooks; hooks != nil && hooks.afterWrite != nil {
		err = hooks.afterWrite(f.file.Name())
		if err != nil {
			f.uncertain = true
		}
	}
	return n, err
}
func (f *historyStageFile) Sync() error {
	f.synced = false
	err := f.file.Sync()
	if err == nil {
		if h := f.reservation.manager.historyStagingHooks; h != nil && h.afterSync != nil {
			err = h.afterSync(f.file.Name())
		}
	}
	if err != nil {
		f.uncertain = true
	} else {
		f.synced = true
	}
	return err
}
func (f *historyStageFile) Close() error {
	if f.closed {
		return ErrHistoryStagingPending
	}
	f.closed = true
	err := f.file.Close()
	if h := f.reservation.manager.historyStagingHooks; h != nil && h.afterClose != nil {
		err = errors.Join(err, h.afterClose(f.file.Name()))
	}
	if err != nil {
		f.uncertain = true
	}
	return err
}
func (f *historyStageFile) binding() (*historyStageBinding, error) {
	if !f.closed || f.uncertain || !f.bodyKnown {
		return nil, ErrHistoryStagingPending
	}
	var header, body []byte
	if f.size > 0 {
		if len(f.header) != historyHeaderBytes {
			return nil, ErrHistoryStagingPending
		}
		header = f.header
		body = f.body.Sum(nil)
	}
	b, err := inspectHistoryStage(f.file.Name(), f.limit, header, body)
	if err != nil || b.Identity != f.identity || b.Size != f.size {
		return nil, errors.Join(ErrHistoryStagingPending, err)
	}
	return b, nil
}
func (r *historyStageReservation) transition(phase string, binding *historyStageBinding) error {
	tx, err := r.manager.acquireWorkflowStoreLease(workflowTransactionLockName)
	if err != nil {
		return err
	}
	if r.file == nil || !r.file.closed || r.file.uncertain || binding == nil {
		return historyStagePending(errors.Join(ErrHistoryStagingPending, r.manager.closeWorkflowStoreLease(tx)))
	}
	r.control.DataWriterClosed = true
	r.control.DataSyncObserved = r.file.synced
	r.control.RemovalObserved = phase == "discarded"
	r.control.Phase = phase
	r.control.Stage = binding
	if phase == "published" {
		r.control.Index = binding
	}
	err = r.writeControl()
	closeErr := r.manager.closeWorkflowStoreLease(tx)
	if err != nil || closeErr != nil {
		r.uncertain = true
		return historyStagePending(errors.Join(err, closeErr))
	}
	return nil
}
func (r *historyStageReservation) Prepared() error {
	if r.file == nil || !r.file.synced {
		return ErrHistoryStagingPending
	}
	b, err := r.file.binding()
	if err != nil {
		return historyStagePending(err)
	}
	if err = r.transition("prepared", b); err != nil {
		return err
	}
	if h := r.manager.historyStagingHooks; h != nil && h.afterPrepared != nil {
		if err = h.afterPrepared(); err != nil {
			return historyStagePending(err)
		}
	}
	return nil
}
func (r *historyStageReservation) Publish(ctx context.Context) error {
	if err := r.checkRoot(); err != nil {
		return err
	}
	// Re-read complete contents outside the short lease, including after the
	// fault/observation hook. No hook can make altered bytes positive proof.
	target := filepath.Join(r.manager.storeRoot, historyIndexName)
	if h := r.manager.historyStagingHooks; h != nil && h.beforePublish != nil {
		if err := h.beforePublish(r.file.file.Name(), target); err != nil {
			return historyStagePending(err)
		}
	}
	stageBinding, stageErr := r.file.binding()
	if stageErr != nil || !sameHistoryStageBinding(stageBinding, r.control.Stage) {
		return historyStagePending(stageErr)
	}
	if r.priorIndex != nil {
		now, err := inspectHistoryStage(target, historyStageMaxBytes, nil, nil)
		if err != nil || !sameHistoryStageBinding(now, r.priorIndex) {
			return historyStagePending(errors.Join(ErrHistoryInventoryStale, err))
		}
	}
	tx, err := r.manager.acquireWorkflowStoreLease(workflowTransactionLockName)
	if err != nil {
		return err
	}
	current, err := r.manager.readWorkflowStoreRevision()
	if err == nil && current != r.control.StoreRevision {
		err = ErrHistoryInventoryStale
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = quickHistoryStageBinding(r.file.file.Name(), r.control.Stage)
	}
	if err == nil && r.priorIndex != nil {
		err = quickHistoryStageBinding(target, r.priorIndex)
	} else if err == nil {
		if _, e := os.Lstat(target); !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(ErrHistoryInventoryStale, e)
		}
	}
	if err == nil {
		err = r.checkRoot()
	}
	if err == nil {
		r.publicationAttempted = true
		err = replaceHistoryIndex(r.file.file.Name(), target)
	}
	if err == nil {
		err = quickHistoryStageBinding(target, r.control.Stage)
	}
	closeErr := r.manager.closeWorkflowStoreLease(tx)
	if err != nil || closeErr != nil {
		return historyStagePending(errors.Join(err, closeErr))
	}
	// Promotion can race an unrelated namespace writer. Verify actual promoted
	// bytes, not only native ID/length, before granting logical slot credit.
	// The full bounded read stays outside every short transaction lease.
	promoted, checkErr := inspectHistoryStage(target, historyStageMaxBytes, r.file.header, r.file.body.Sum(nil))
	if checkErr != nil || !sameHistoryStageBinding(promoted, r.control.Stage) {
		return historyStagePending(checkErr)
	}
	final, err := r.manager.acquireWorkflowStoreLease(workflowTransactionLockName)
	if err != nil {
		return err
	}
	if err = quickHistoryStageBinding(target, promoted); err == nil {
		err = r.checkRoot()
	}
	if err == nil {
		r.control.Phase = "published"
		r.control.PublicationObserved = true
		r.control.Index = promoted
		err = r.writeControl()
	}
	closeErr = r.manager.closeWorkflowStoreLease(final)
	if err != nil || closeErr != nil {
		return historyStagePending(errors.Join(err, closeErr))
	}
	r.finished = true
	return nil
}
func (r *historyStageReservation) FinishFailure(err error) error {
	if r.finished {
		return err
	}
	if r.file != nil && !r.file.closed {
		err = errors.Join(err, r.file.Close())
	}
	if !r.uncertain && r.file != nil && !r.file.uncertain && !r.publicationAttempted && historyDiscardableStageError(err) {
		b, checkErr := r.file.binding()
		if checkErr == nil {
			named, e := os.Lstat(r.file.file.Name())
			if e == nil && !os.SameFile(r.file.initial, named) {
				e = ErrHistoryStagingPending
			}
			if e == nil {
				e = os.Remove(r.file.file.Name())
			}
			if e == nil {
				if e = r.transition("discarded", b); e == nil {
					r.finished = true
					return err
				}
			}
			checkErr = e
		}
		err = errors.Join(err, checkErr)
	}
	return historyStagePending(err)
}
