//go:build !linux || (!amd64 && !arm64)

package audit

import "context"

func LocalRecordingSupported() bool { return false }

func InitializeLocalJournal(directory string) (Checkpoint, error) {
	return Checkpoint{}, ErrLocalStorageUnsupported
}
func OpenLocalJournal(ctx context.Context, directory string, genesis, head Checkpoint) (LocalJournal, error) {
	return nil, ErrLocalStorageUnsupported
}
