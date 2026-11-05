//go:build darwin && (amd64 || arm64)

package audit

import (
	"context"
	"io"
)

func LocalRecordingSupported() bool { return true }

func InitializeLocalJournal(directory string) (Checkpoint, error) {
	return initializeDarwinLocalJournal(directory)
}

func OpenLocalJournal(ctx context.Context, directory string, genesis, head Checkpoint) (LocalJournal, error) {
	return openDarwinLocalJournal(ctx, directory, genesis, head)
}

func ExportLocalSegment(ctx context.Context, directory string, genesis, head Checkpoint, out io.Writer) error {
	return exportDarwinLocalSegment(ctx, directory, genesis, head, out)
}
