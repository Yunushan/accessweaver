//go:build windows && (amd64 || arm64)

package audit

import (
	"context"
	"io"
)

func LocalRecordingSupported() bool { return true }

func InitializeLocalJournal(directory string) (Checkpoint, error) {
	return initializeWindowsLocalJournal(directory)
}

func OpenLocalJournal(ctx context.Context, directory string, genesis, head Checkpoint) (LocalJournal, error) {
	return openWindowsLocalJournal(ctx, directory, genesis, head)
}

func ExportLocalSegment(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) error {
	return exportWindowsLocalSegment(ctx, directory, genesis, head, out)
}
