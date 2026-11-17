package workflow

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	ErrHistoryInventoryNeeded   = errors.New("workflow history inventory capture is required")
	ErrHistoryInventoryStale    = errors.New("workflow history inventory changed; capture or reload it again")
	ErrHistoryInvalidRequest    = errors.New("invalid workflow history request")
	ErrHistoryRecordUnavailable = errors.New("workflow history record is unavailable")
	ErrHistoryCapacity          = errors.New("workflow history inventory exceeds its supported capacity; all evidence retained")
	ErrHistoryUnavailable       = errors.New("workflow history inventory is unavailable; all evidence retained")
)

type HistoryInventory struct {
	Snapshot      string    `json:"snapshot"`
	StoreRevision string    `json:"storeRevision"`
	CreatedAt     time.Time `json:"createdAt"`
	Count         uint64    `json:"count"`
	TotalBytes    int64     `json:"totalBytes"`
}

type HistoryPageQuery struct {
	Limit    int
	Cursor   string
	Snapshot string
}
type HistoryPage struct {
	Inventory  HistoryInventory       `json:"inventory"`
	Items      []HistoryRecordSummary `json:"items"`
	NextCursor string                 `json:"nextCursor,omitempty"`
}

type HistoryRecordSummary struct {
	RecordRef      string    `json:"recordRef"`
	Revision       string    `json:"revision"`
	ID             string    `json:"id,omitempty"`
	Action         string    `json:"action,omitempty"`
	State          string    `json:"state"`
	StartedAt      time.Time `json:"startedAt,omitempty,omitzero"`
	FinishedAt     time.Time `json:"finishedAt,omitempty,omitzero"`
	Size           int64     `json:"size"`
	Classification string    `json:"classification"`
	Protection     string    `json:"protection"`
	ErrorPresent   bool      `json:"errorPresent"`
	ResultPresent  bool      `json:"resultPresent"`
	RawAvailable   bool      `json:"rawAvailable"`
}

type HistoryRecordDetail struct {
	Record       HistoryRecordSummary `json:"record"`
	Job          *Job                 `json:"job,omitempty"`
	RawAvailable bool                 `json:"rawAvailable"`
}

// History failures print fixed text while retaining original local causes.
type historyFailure struct{ category, cause error }

func (e *historyFailure) Error() string   { return e.category.Error() }
func (e *historyFailure) Unwrap() []error { return []error{e.category, e.cause} }
func historyError(category, cause error) error {
	if cause == nil {
		return category
	}
	if category == ErrHistoryUnavailable && errors.Is(cause, ErrHistoryCapacity) {
		category = ErrHistoryCapacity
	}
	return &historyFailure{category: category, cause: cause}
}

// Capture is the explicit, mutating inventory action. Pages and selected-record
// reads never create a store, initialize an epoch or repair an index.
func (m *Manager) CaptureHistoryInventory(ctx context.Context) (HistoryInventory, error) {
	return m.captureHistoryInventory(ctx)
}
func (m *Manager) HistoryPage(ctx context.Context, query HistoryPageQuery) (HistoryPage, error) {
	return m.readHistoryPage(ctx, query)
}
func (m *Manager) ReadHistoryRecord(ctx context.Context, recordRef, revision string) (HistoryRecordDetail, error) {
	return m.readHistoryRecord(ctx, recordRef, revision)
}
func (m *Manager) ReadHistoryRecordRaw(ctx context.Context, recordRef, revision string) ([]byte, error) {
	return m.readHistoryRecordRaw(ctx, recordRef, revision)
}
func WriteHistoryRecordDetailJSON(out io.Writer, detail HistoryRecordDetail) error {
	return writeHistoryRecordDetailJSON(out, detail)
}
