package workflow

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
	"syscall"
	"time"
)

// Lifecycle receipts describe only this controller's local record, workdir and
// observed owner releases. They never authorize retirement, certify a vendor's
// effects or establish power-loss durability. Missing legacy receipts do not
// invent an active generation.
const (
	workflowLifecycleDirectory       = ".workflow-lifecycle"
	workflowLifecycleCurrent         = ".workflow-lifecycle.current"
	workflowLifecycleMaxGenerations  = 4096
	workflowLifecycleMaxReceiptBytes = 64 << 10
)

var (
	ErrWorkflowLifecycle        = errors.New("workflow local lifecycle evidence is unavailable")
	ErrWorkflowLifecyclePending = errors.New("workflow local lifecycle requires explicit review")
)

// WorkflowLifecycleStatus is the current LOCAL receipt projection. A false
// AdmissionBlocked is not an admission grant: policy, active locks, orphan scans,
// metadata capacity and other store failures are checked separately by Start.
type WorkflowLifecycleStatus struct {
	State            string `json:"state"`
	JobID            string `json:"jobId,omitempty"`
	AdmissionBlocked bool   `json:"admissionBlocked"`
	Protection       string `json:"protection"`
}

type workflowLifecycleIntent struct {
	Version                 int       `json:"version"`
	Generation              string    `json:"generation"`
	Nonce                   string    `json:"nonce"`
	Action                  string    `json:"action"`
	RequestSHA256           string    `json:"requestSHA256"`
	CreatedAt               time.Time `json:"createdAt"`
	ControllerStorageSHA256 string    `json:"controllerStorageSHA256,omitempty"`
}
type workflowLifecyclePointer struct {
	Version      int    `json:"version"`
	Generation   string `json:"generation"`
	IntentSHA256 string `json:"intentSHA256"`
}
type workflowLifecycleSeal struct {
	Version               int                       `json:"version"`
	IntentSHA256          string                    `json:"intentSHA256"`
	RecordSHA256          string                    `json:"recordSHA256,omitempty"`
	RecordState           string                    `json:"recordState"`
	Categories            []string                  `json:"categories"`
	Manifest              workflowLifecycleManifest `json:"manifest"`
	LocalReleasePermitted bool                      `json:"localReleasePermitted"`
	Protection            string                    `json:"protection"`
}
type workflowLifecycleAck struct {
	Version             int    `json:"version"`
	IntentSHA256        string `json:"intentSHA256"`
	SealSHA256          string `json:"sealSHA256"`
	LocalOwnersReleased bool   `json:"localOwnersReleased"`
	Protection          string `json:"protection"`
}
type workflowLifecycleReceipt struct {
	Version      int                     `json:"version"`
	Intent       workflowLifecycleIntent `json:"intent"`
	IntentSHA256 string                  `json:"intentSHA256"`
	Seal         *workflowLifecycleSeal  `json:"seal,omitempty"`
	SealSHA256   string                  `json:"sealSHA256,omitempty"`
	Ack          *workflowLifecycleAck   `json:"ack,omitempty"`
}
type workflowLifecycle struct {
	receipt               workflowLifecycleReceipt
	initialMetadataClosed bool
	sealPublished         bool
	sealTransactionClosed bool
	ackObservation        ackObservation
}

func workflowLifecycleHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func workflowLifecycleJSONHash(value any) string {
	b, _ := json.Marshal(value)
	return workflowLifecycleHash(b)
}
func workflowLifecycleError(cause error) error { return workflowFailure(ErrWorkflowLifecycle, cause) }
func workflowLifecyclePending(cause error) error {
	return workflowLifecycleError(errors.Join(ErrWorkflowLifecyclePending, cause))
}

func decodeWorkflowLifecycle(b []byte, value any) error {
	if len(b) == 0 || len(b) > workflowLifecycleMaxReceiptBytes {
		return ErrWorkflowLifecycle
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrWorkflowLifecycle
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(b, canonical) {
		return ErrWorkflowLifecycle
	}
	return nil
}

// Reads retain exact opened/named identity and observe every owned Close. An
// error is never reconstructed from persisted Job.Error or other private text.
func readWorkflowLifecycleFile(ctx context.Context, path string, limit int64) (b []byte, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	named, cause := os.Lstat(path)
	if cause != nil {
		return nil, cause
	}
	if !named.Mode().IsRegular() || named.Size() < 0 || named.Size() > limit {
		return nil, ErrWorkflowLifecycle
	}
	file, cause := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if cause != nil {
		return nil, cause
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			b = nil
			err = errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
		}
	}()
	opened, cause := file.Stat()
	if cause != nil {
		return nil, cause
	}
	if !opened.Mode().IsRegular() || !os.SameFile(named, opened) {
		return nil, ErrWorkflowLifecycle
	}
	b, cause = io.ReadAll(io.LimitReader(workflowContextReader{ctx, file}, limit+1))
	if contextErr := ctx.Err(); contextErr != nil {
		if cause != nil && cause != contextErr {
			return nil, errors.Join(cause, contextErr)
		}
		return nil, contextErr
	}
	if cause != nil {
		return nil, cause
	}
	if int64(len(b)) > limit {
		return nil, ErrWorkflowLifecycle
	}
	after, cause := file.Stat()
	if cause != nil {
		return nil, cause
	}
	current, cause := os.Lstat(path)
	if cause != nil {
		return nil, cause
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, after) || !os.SameFile(after, current) || opened.Size() != after.Size() || opened.ModTime() != after.ModTime() || int64(len(b)) != after.Size() {
		return nil, ErrWorkflowLifecycle
	}
	return b, nil
}

// privatefile provides privacy before payload on every supported platform.
// Unknown/partially written metadata is preserved. Publishing a receipt never
// overwrites an unknown destination; replacement requires its exact old hash.
func writeWorkflowLifecycleFile(path string, b []byte, previous string) error {
	return writeLifecycleObserved(path, b, previous, nil).Err
}

func (m *Manager) lifecycleWrite(path string, b []byte, previous string) error {
	return m.observedLifecycleWrite(path, b, previous).Err
}
func (m *Manager) lifecycleReceiptPath(id, phase string) string {
	return filepath.Join(m.storeRoot, workflowLifecycleDirectory, id+"."+phase+".json")
}

func workflowLifecycleWithinByteLimit(receipt workflowLifecycleReceipt) bool {
	total := 0
	values := []any{receipt.Intent}
	if receipt.Seal != nil {
		values = append(values, receipt.Seal)
	}
	if receipt.Ack != nil {
		values = append(values, receipt.Ack)
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > workflowLifecycleMaxReceiptBytes-total {
			return false
		}
		total += len(encoded)
	}
	return true
}

func validWorkflowLifecycleReceipt(receipt workflowLifecycleReceipt) bool {
	intent := receipt.Intent
	if !workflowLifecycleWithinByteLimit(receipt) || receipt.Version != 1 || intent.Version != 1 || !historyHex(intent.Generation, 48) || !historyHex(intent.Nonce, 48) || !historyHex(intent.RequestSHA256, 64) || (intent.ControllerStorageSHA256 != "" && !historyHex(intent.ControllerStorageSHA256, 64)) || intent.CreatedAt.IsZero() || !knownWorkflowLifecycleAction(intent.Action) || receipt.IntentSHA256 != workflowLifecycleJSONHash(intent) {
		return false
	}
	if receipt.Seal == nil {
		return receipt.SealSHA256 == "" && receipt.Ack == nil
	}
	seal := receipt.Seal
	if seal.Version != 1 || seal.IntentSHA256 != receipt.IntentSHA256 || seal.Protection != "retirement-unavailable" || (seal.RecordState != "observed" && seal.RecordState != "unavailable") || seal.RecordState == "observed" && !historyHex(seal.RecordSHA256, 64) || seal.RecordState == "unavailable" && seal.RecordSHA256 != "" || receipt.SealSHA256 != workflowLifecycleJSONHash(*seal) || !validWorkflowLifecycleManifest(seal.Manifest) {
		return false
	}
	if !validWorkflowLifecycleCategories(seal.Categories) || seal.LocalReleasePermitted && (seal.RecordState != "observed" || workflowLifecycleUncertainCategories(seal.Categories)) {
		return false
	}
	ack := receipt.Ack
	return ack == nil || ack.Version == 1 && ack.IntentSHA256 == receipt.IntentSHA256 && ack.SealSHA256 == receipt.SealSHA256 && ack.LocalOwnersReleased && ack.Protection == "retirement-unavailable" && seal.LocalReleasePermitted
}
func knownWorkflowLifecycleAction(action string) bool {
	for _, operation := range Catalog() {
		if action == operation.ID {
			return true
		}
	}
	return false
}

// Observe only: no directory/lock creation, no recovery, no stale-PID probe.
func (m *Manager) LifecycleStatus(ctx context.Context) (WorkflowLifecycleStatus, error) {
	status := WorkflowLifecycleStatus{State: "none", Protection: "retirement-unavailable"}
	pointer, receipt, cause := m.readWorkflowLifecycleCurrent(ctx)
	if cause != nil {
		status.State = "blocked"
		status.AdmissionBlocked = true
		return status, workflowLifecyclePending(cause)
	}
	if pointer == nil {
		return status, nil
	}
	status.JobID = receipt.Intent.Generation
	status.State = "intent"
	status.AdmissionBlocked = true
	if receipt.Seal != nil {
		status.State = "sealed"
	}
	if receipt.Ack != nil {
		status.State = "released"
		status.AdmissionBlocked = false
	}
	return status, nil
}

func (m *Manager) readWorkflowLifecycleCurrent(ctx context.Context) (*workflowLifecyclePointer, workflowLifecycleReceipt, error) {
	var receipt workflowLifecycleReceipt
	dir := filepath.Join(m.storeRoot, workflowLifecycleDirectory)
	pointerBytes, cause := readWorkflowLifecycleFile(ctx, filepath.Join(m.storeRoot, workflowLifecycleCurrent), workflowLifecycleMaxReceiptBytes)
	if errors.Is(cause, os.ErrNotExist) {
		named, dirErr := os.Lstat(dir)
		if errors.Is(dirErr, os.ErrNotExist) {
			return nil, receipt, nil
		}
		if dirErr != nil || named.Mode()&os.ModeType != os.ModeDir {
			return nil, receipt, errors.Join(ErrWorkflowLifecycle, dirErr)
		}
		directory, dirErr := os.Open(dir)
		if dirErr != nil {
			return nil, receipt, dirErr
		}
		entries, readErr := directory.ReadDir(1)
		closeErr := directory.Close()
		if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) != 0 {
			return nil, receipt, errors.Join(ErrWorkflowLifecyclePending, readErr, workflowFailure(ErrWorkflowCleanup, closeErr))
		}
		return nil, receipt, nil
	}
	if cause != nil {
		return nil, receipt, cause
	}
	var pointer workflowLifecyclePointer
	if decodeWorkflowLifecycle(pointerBytes, &pointer) != nil || pointer.Version != 1 || !historyHex(pointer.Generation, 48) || !historyHex(pointer.IntentSHA256, 64) {
		return nil, receipt, ErrWorkflowLifecycle
	}
	named, cause := os.Lstat(dir)
	if cause != nil || named.Mode()&os.ModeType != os.ModeDir {
		return nil, receipt, errors.Join(ErrWorkflowLifecycle, cause)
	}
	receipt, cause = m.readWorkflowLifecycleChain(ctx, pointer.Generation)
	if cause == context.Canceled || cause == context.DeadlineExceeded {
		return nil, receipt, cause
	}
	if cause != nil || receipt.IntentSHA256 != pointer.IntentSHA256 {
		return nil, receipt, errors.Join(ErrWorkflowLifecycle, cause)
	}
	current, cause := os.Lstat(dir)
	if cause != nil || !current.IsDir() || !os.SameFile(named, current) {
		return nil, receipt, errors.Join(ErrWorkflowLifecycle, cause)
	}
	latest, readErr := readWorkflowLifecycleFile(ctx, filepath.Join(m.storeRoot, workflowLifecycleCurrent), workflowLifecycleMaxReceiptBytes)
	if readErr == context.Canceled || readErr == context.DeadlineExceeded {
		return nil, receipt, readErr
	}
	if readErr != nil || !bytes.Equal(latest, pointerBytes) {
		return nil, receipt, errors.Join(ErrWorkflowLifecycle, readErr)
	}
	return &pointer, receipt, nil
}

func (m *Manager) readWorkflowLifecycleChain(ctx context.Context, id string) (receipt workflowLifecycleReceipt, err error) {
	if !historyHex(id, 48) {
		return receipt, ErrWorkflowLifecycle
	}
	intent, cause := readWorkflowLifecycleFile(ctx, m.lifecycleReceiptPath(id, "intent"), workflowLifecycleMaxReceiptBytes)
	if cause != nil {
		return receipt, cause
	}
	total := len(intent)
	receipt.Version = 1
	if cause = decodeWorkflowLifecycle(intent, &receipt.Intent); cause != nil {
		return receipt, cause
	}
	receipt.IntentSHA256 = workflowLifecycleHash(intent)
	seal, cause := readWorkflowLifecycleFile(ctx, m.lifecycleReceiptPath(id, "seal"), workflowLifecycleMaxReceiptBytes)
	if cause != nil && !errors.Is(cause, os.ErrNotExist) {
		return receipt, cause
	}
	if cause == nil {
		total += len(seal)
		receipt.Seal = &workflowLifecycleSeal{}
		if cause = decodeWorkflowLifecycle(seal, receipt.Seal); cause != nil {
			return receipt, cause
		}
		receipt.SealSHA256 = workflowLifecycleHash(seal)
	}
	ack, cause := readWorkflowLifecycleFile(ctx, m.lifecycleReceiptPath(id, "ack"), workflowLifecycleMaxReceiptBytes)
	if cause != nil && !errors.Is(cause, os.ErrNotExist) {
		return receipt, cause
	}
	if cause == nil {
		total += len(ack)
		receipt.Ack = &workflowLifecycleAck{}
		if cause = decodeWorkflowLifecycle(ack, receipt.Ack); cause != nil {
			return receipt, cause
		}
	}
	if total > workflowLifecycleMaxReceiptBytes || !validWorkflowLifecycleReceipt(receipt) || receipt.Intent.Generation != id {
		return receipt, ErrWorkflowLifecycle
	}
	return receipt, nil
}

// Admission additionally scans bounded metadata names, including orphan intents
// from a crash before current-pointer publication. No uncertainty is deleted or
// silently converted into a fresh generation. Status itself stays a small read.
func (m *Manager) inspectWorkflowLifecycleAdmission(ctx context.Context) (generations int, err error) {
	if cause := m.checkReconciliationAdmission(ctx); cause != nil {
		return 0, cause
	}
	if cause := ctx.Err(); cause != nil {
		return 0, cause
	}
	config, cause := os.Open(m.storeRoot)
	if cause != nil {
		return 0, cause
	}
	rootEntries, readErr := config.ReadDir(65537)
	closeErr := config.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(rootEntries) > 65536 {
		return 0, errors.Join(ErrWorkflowLifecycle, readErr, workflowFailure(ErrWorkflowCleanup, closeErr))
	}
	for _, entry := range rootEntries {
		if strings.HasPrefix(entry.Name(), ".lifecycle-") {
			return 0, ErrWorkflowLifecyclePending
		}
	}
	pointer, current, cause := m.readWorkflowLifecycleCurrent(ctx)
	if cause != nil {
		return 0, cause
	}
	dir := filepath.Join(m.storeRoot, workflowLifecycleDirectory)
	named, cause := os.Lstat(dir)
	if errors.Is(cause, os.ErrNotExist) {
		if pointer != nil {
			return 0, ErrWorkflowLifecycle
		}
		return 0, nil
	}
	if cause != nil || named.Mode()&os.ModeType != os.ModeDir {
		return 0, errors.Join(ErrWorkflowLifecycle, cause)
	}
	directory, cause := os.Open(dir)
	if cause != nil {
		return 0, cause
	}
	entries, readErr := directory.ReadDir(workflowLifecycleMaxGenerations*3 + 1)
	opened, statErr := directory.Stat()
	closeErr = directory.Close()
	if readErr != nil && readErr != io.EOF || statErr != nil || closeErr != nil || opened != nil && !os.SameFile(named, opened) || len(entries) > workflowLifecycleMaxGenerations*3 {
		return 0, errors.Join(ErrWorkflowLifecycle, readErr, statErr, workflowFailure(ErrWorkflowCleanup, closeErr))
	}
	names := map[string]uint8{}
	sizes := map[string]int64{}
	for _, entry := range entries {
		if cause = ctx.Err(); cause != nil {
			return 0, cause
		}
		name := entry.Name()
		parts := strings.Split(name, ".")
		if len(parts) != 3 || !historyHex(parts[0], 48) || parts[2] != "json" {
			return 0, ErrWorkflowLifecyclePending
		}
		bit := uint8(0)
		switch parts[1] {
		case "intent":
			bit = 1
		case "seal":
			bit = 2
		case "ack":
			bit = 4
		default:
			return 0, ErrWorkflowLifecyclePending
		}
		info, cause := entry.Info()
		if cause != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > workflowLifecycleMaxReceiptBytes {
			return 0, errors.Join(ErrWorkflowLifecycle, cause)
		}
		names[parts[0]] |= bit
		sizes[parts[0]] += info.Size()
		if sizes[parts[0]] > workflowLifecycleMaxReceiptBytes {
			return 0, ErrWorkflowLifecycle
		}
	}
	if len(names) > workflowLifecycleMaxGenerations || pointer == nil && len(names) > 0 {
		return 0, ErrWorkflowLifecyclePending
	}
	for id, bits := range names {
		if cause = ctx.Err(); cause != nil {
			return 0, cause
		}
		if bits != 7 {
			return 0, ErrWorkflowLifecyclePending
		}
		receipt, cause := m.readWorkflowLifecycleChain(ctx, id)
		if cause == context.Canceled || cause == context.DeadlineExceeded {
			return 0, cause
		}
		if cause != nil || receipt.Ack == nil {
			return 0, errors.Join(ErrWorkflowLifecyclePending, cause)
		}
	}
	if pointer != nil && current.Ack == nil {
		return 0, ErrWorkflowLifecyclePending
	}
	after, cause := os.Lstat(dir)
	if cause != nil || !after.IsDir() || !os.SameFile(named, after) {
		return 0, errors.Join(ErrWorkflowLifecycle, cause)
	}
	return len(names), nil
}

func (m *Manager) beginWorkflowLifecycle(ctx context.Context, job Job, request Request) (state *workflowLifecycle, err error) {
	if cause := ctx.Err(); cause != nil {
		return nil, cause
	}
	transaction, cause := m.acquireWorkflowStoreLease(workflowTransactionLockName)
	if cause != nil {
		return nil, cause
	}
	defer func() {
		if closeErr := workflowFailure(ErrWorkflowCleanup, m.closeWorkflowStoreLease(transaction)); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	generations, cause := m.inspectWorkflowLifecycleAdmission(ctx)
	if cause == context.Canceled || cause == context.DeadlineExceeded {
		return nil, cause
	}
	if cause != nil {
		return nil, workflowLifecyclePending(cause)
	}
	if generations >= workflowLifecycleMaxGenerations {
		return nil, workflowLifecyclePending(ErrHistoryCapacity)
	}
	pointer, previous, cause := m.readWorkflowLifecycleCurrent(ctx)
	if cause == context.Canceled || cause == context.DeadlineExceeded {
		return nil, cause
	}
	if cause != nil {
		return nil, workflowLifecyclePending(cause)
	}
	if pointer != nil && previous.Ack == nil {
		return nil, workflowLifecyclePending(nil)
	}
	dir := filepath.Join(m.storeRoot, workflowLifecycleDirectory)
	if cause = os.Mkdir(dir, 0700); cause != nil && !errors.Is(cause, os.ErrExist) {
		return nil, workflowLifecycleError(cause)
	}
	named, cause := os.Lstat(dir)
	if cause != nil || named.Mode()&os.ModeType != os.ModeDir {
		return nil, workflowLifecycleError(errors.Join(ErrWorkflowLifecycle, cause))
	}
	// A newly accepted generation never adopts an existing record/workdir.
	for _, path := range []string{filepath.Join(m.root, job.ID+".json"), filepath.Join(m.root, job.ID)} {
		if _, cause = os.Lstat(path); !errors.Is(cause, os.ErrNotExist) {
			return nil, workflowLifecyclePending(errors.Join(ErrWorkflowLifecycle, cause))
		}
	}
	nonce, cause := newHistoryRevision()
	if cause != nil {
		return nil, workflowLifecycleError(cause)
	}
	requestBytes, cause := json.Marshal(request)
	if cause != nil {
		return nil, workflowLifecycleError(cause)
	}
	intent := workflowLifecycleIntent{Version: 1, Generation: job.ID, Nonce: nonce, Action: job.Action, RequestSHA256: workflowLifecycleHash(requestBytes), CreatedAt: time.Now().UTC()}
	m.mu.Lock()
	budget := m.controllerBudget
	m.mu.Unlock()
	if budget != nil && budget.reservation.Generation == job.ID {
		intent.ControllerStorageSHA256 = budget.binding.digest()
	}
	receipt := workflowLifecycleReceipt{Version: 1, Intent: intent, IntentSHA256: workflowLifecycleJSONHash(intent)}
	b, _ := json.Marshal(intent)
	// Before this boundary cancellation is a refusal with no generation writes.
	// Once publication begins, finish its owned writes/closures regardless of
	// cancellation; any failure remains durable uncertainty, never clean cancel.
	if cause = ctx.Err(); cause != nil {
		return nil, cause
	}
	intentObservation := m.observedLifecycleWrite(m.lifecycleReceiptPath(job.ID, "intent"), b, "")
	if cause = intentObservation.Err; cause != nil {
		return nil, workflowLifecycleError(cause)
	}
	next := workflowLifecyclePointer{1, job.ID, receipt.IntentSHA256}
	nextBytes, _ := json.Marshal(next)
	oldHash := ""
	if pointer != nil {
		oldBytes, _ := json.Marshal(pointer)
		oldHash = workflowLifecycleHash(oldBytes)
	}
	pointerObservation := m.observedLifecycleWrite(filepath.Join(m.storeRoot, workflowLifecycleCurrent), nextBytes, oldHash)
	if cause = pointerObservation.Err; cause != nil {
		return nil, workflowLifecycleError(cause)
	}
	return &workflowLifecycle{receipt: receipt, initialMetadataClosed: intentObservation.Known && intentObservation.Published && pointerObservation.Known && pointerObservation.Published}, nil
}

func (m *Manager) sealWorkflowLifecycle(state *workflowLifecycle, job Job, outcome error) (err error) {
	if state == nil {
		return nil
	}
	seal := workflowLifecycleSeal{Version: 1, IntentSHA256: state.receipt.IntentSHA256, RecordState: "unavailable", Categories: workflowLifecycleCategories(outcome), Protection: "retirement-unavailable"}
	expected, cause := encodeJob(job)
	if cause == nil {
		observed, readErr := readWorkflowLifecycleFile(context.Background(), filepath.Join(m.root, job.ID+".json"), maxHistoryRecordBytes)
		if readErr == nil && bytes.Equal(expected, observed) {
			seal.RecordState = "observed"
			seal.RecordSHA256 = workflowLifecycleHash(observed)
		} else {
			cause = errors.Join(ErrWorkflowPersistence, readErr)
		}
	}
	if !state.initialMetadataClosed {
		cause = errors.Join(cause, workflowFailure(ErrWorkflowPersistence, ErrLifecycleReconciliationUnavailable))
	}
	manifest, manifestErr := m.collectWorkflowLifecycleManifest(job.ID)
	seal.Manifest = manifest
	if manifestErr != nil {
		cause = errors.Join(cause, manifestErr)
	}
	seal.Categories = workflowLifecycleCategories(errors.Join(outcome, cause))
	seal.LocalReleasePermitted = cause == nil && !workflowLifecycleUncertainCategories(seal.Categories)
	next := state.receipt
	next.Seal = &seal
	next.SealSHA256 = workflowLifecycleJSONHash(seal)
	if !workflowLifecycleWithinByteLimit(next) {
		return workflowLifecycleError(ErrWorkflowLifecycle)
	}
	b, encodeErr := json.Marshal(seal)
	if encodeErr != nil {
		return workflowLifecycleError(encodeErr)
	}
	// The original active owner protects collection. Only publication holds
	// the short transaction lease; never hash an entire workdir under it.
	transaction, transactionErr := m.acquireWorkflowStoreLease(workflowTransactionLockName)
	if transactionErr != nil {
		return workflowLifecycleError(errors.Join(cause, transactionErr))
	}
	defer func() {
		closeErr := m.closeWorkflowStoreLease(transaction)
		state.sealTransactionClosed = closeErr == nil
		err = errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
	}()
	pointer, current, currentErr := m.readWorkflowLifecycleCurrent(context.Background())
	if currentErr != nil || pointer == nil || pointer.Generation != job.ID || current.IntentSHA256 != state.receipt.IntentSHA256 || current.Seal != nil || current.Ack != nil {
		return workflowLifecyclePending(errors.Join(cause, currentErr, ErrWorkflowLifecycle))
	}
	observation := m.observedLifecycleWrite(m.lifecycleReceiptPath(job.ID, "seal"), b, "")
	if observation.Err != nil {
		return workflowLifecycleError(errors.Join(cause, observation.Err))
	}
	state.sealPublished = observation.Known && observation.Published
	state.receipt = next
	return workflowLifecycleError(cause)
}

func (m *Manager) acknowledgeWorkflowLifecycle(state *workflowLifecycle) (err error) {
	if state == nil || state.receipt.Seal == nil || !state.receipt.Seal.LocalReleasePermitted || !state.sealPublished || !state.sealTransactionClosed {
		return workflowLifecyclePending(nil)
	}
	transaction, cause := m.acquireWorkflowStoreLease(workflowTransactionLockName)
	if cause != nil {
		return workflowLifecycleError(cause)
	}
	// This acknowledgement certifies prior data/output owners and the ORIGINAL
	// active lease only. It cannot recursively certify Close of its own writer
	// or this short coordination lease. Current acquisition supplies exclusion.
	defer func() {
		closeErr := m.closeWorkflowStoreLease(transaction)
		state.ackObservation.TransactionClosed = closeErr == nil
		err = errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
	}()
	pointer, current, cause := m.readWorkflowLifecycleCurrent(context.Background())
	if cause != nil || pointer == nil || pointer.Generation != state.receipt.Intent.Generation || current.IntentSHA256 != state.receipt.IntentSHA256 || current.SealSHA256 != state.receipt.SealSHA256 || current.Ack != nil {
		return workflowLifecyclePending(errors.Join(ErrWorkflowLifecycle, cause))
	}
	next := state.receipt
	next.Ack = &workflowLifecycleAck{1, next.IntentSHA256, next.SealSHA256, true, "retirement-unavailable"}
	if !workflowLifecycleWithinByteLimit(next) {
		return workflowLifecycleError(ErrWorkflowLifecycle)
	}
	b, _ := json.Marshal(next.Ack)
	state.ackObservation.Write = m.observedLifecycleWrite(m.lifecycleReceiptPath(next.Intent.Generation, "ack"), b, "")
	if cause = state.ackObservation.Write.Err; cause != nil {
		return workflowLifecycleError(cause)
	}
	state.receipt = next
	return nil
}

var workflowLifecycleCategoryTable = []struct {
	name     string
	category error
}{
	{"admission", ErrWorkflowAdmission}, {"execution", ErrWorkflowExecution}, {"result", ErrWorkflowResult}, {"persistence", ErrWorkflowPersistence}, {"cleanup", ErrWorkflowCleanup}, {"store", ErrWorkflowStore}, {"lifecycle", ErrWorkflowLifecycle},
}

func workflowLifecycleCategories(cause error) []string {
	categories := []string{}
	for _, item := range workflowLifecycleCategoryTable {
		if errors.Is(cause, item.category) {
			categories = append(categories, item.name)
		}
	}
	return categories
}
func validWorkflowLifecycleCategories(categories []string) bool {
	next := 0
	for _, category := range categories {
		found := false
		for next < len(workflowLifecycleCategoryTable) {
			item := workflowLifecycleCategoryTable[next]
			next++
			if category == item.name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func workflowLifecycleUncertainCategories(categories []string) bool {
	for _, category := range categories {
		if category == "result" || category == "persistence" || category == "cleanup" || category == "store" || category == "lifecycle" {
			return true
		}
	}
	return false
}
