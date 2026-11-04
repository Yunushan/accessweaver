package audit

import (
	"context"
	"errors"
)

var ErrLocalStorageUnsupported = errors.New("protected local audit recording is unavailable on this target")

// LocalJournal records for an OS-derived, locally initialized producer. Opening
// it does not authenticate enrollment or establish collector acknowledgment.
// Implementations must hold a single-writer lock and preserve uncertain writes.
type LocalJournal interface {
	Append(context.Context, Event) (Checkpoint, error)
	Snapshot(context.Context) ([]byte, Checkpoint, Checkpoint, error)
	Close() error
}
