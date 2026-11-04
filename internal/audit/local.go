package audit

import (
	"context"
	"errors"
)

const actorKeyName = ".actor-key"
const actorKeyPrefix = "AccessWeaver audit actor key v1\n"
const actorKeyFileBytes = len(actorKeyPrefix) + 32

var ErrLocalStorageUnsupported = errors.New("protected local audit storage is unavailable on this target")
var ErrExportDestination = errors.New("audit export output must not alias the source journal, actor key or checkpoint inputs")
var ErrExportOutput = errors.New("audit export output unavailable or partial; inspect the output before using it")

// LocalJournal records for an OS-derived, locally initialized producer. Opening
// it does not authenticate enrollment or establish collector acknowledgment.
// Implementations must hold a single-writer lock and preserve uncertain writes.
type LocalJournal interface {
	Append(context.Context, Event) (Checkpoint, error)
	Snapshot(context.Context) ([]byte, Checkpoint, Checkpoint, error)
	Close() error
}
