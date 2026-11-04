package audit

import "errors"

const journalName = "events.journal"
const MaxJournalBytes = MaxCheckpointBytes + MaxSegmentBytes

var (
	ErrJournalBusy        = errors.New("audit journal is locked by another writer")
	ErrJournalStorage     = errors.New("audit journal storage or retained checkpoints differ")
	ErrJournalUnavailable = errors.New("audit journal is closed or requires reconciliation")
	ErrJournalUncertain   = errors.New("audit journal write durability is uncertain; preserve storage and reconcile independently")
	ErrJournalFull        = errors.New("audit journal is full; independently acknowledged retention is required")
)

type journalCommitter interface {
	WriteAt([]byte, int64) (int, error)
	Sync() error
}

func commitJournalBytes(disk journalCommitter, data []byte, offset int64) error {
	n, err := disk.WriteAt(data, offset)
	if err != nil || n != len(data) {
		return ErrJournalUncertain
	}
	if disk.Sync() != nil {
		return ErrJournalUncertain
	}
	return nil
}
