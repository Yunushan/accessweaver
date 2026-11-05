//go:build (!linux && !windows) || (!amd64 && !arm64)

package audit

import (
	"context"
	"io"
)

func LocalRecordingSupported() bool { return false }

func InitializeLocalJournal(directory string) (Checkpoint, error) {
	return Checkpoint{}, ErrLocalStorageUnsupported
}
func OpenLocalJournal(ctx context.Context, directory string, genesis, head Checkpoint) (LocalJournal, error) {
	return nil, ErrLocalStorageUnsupported
}

func ExportLocalSegment(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) error {
	return ErrLocalStorageUnsupported
}
