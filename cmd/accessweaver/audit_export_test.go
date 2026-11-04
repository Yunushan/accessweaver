package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
)

func TestAuditExportConsentAndAmbiguousOptionsRefuseBeforeAnyRead(t *testing.T) {
	reads, exports := 0, 0
	read := func(context.Context, string, int64) ([]byte, error) { reads++; return nil, errors.New("must not read") }
	export := func(context.Context, string, audit.Checkpoint, audit.Checkpoint, io.Writer) error {
		exports++
		return nil
	}
	for _, args := range [][]string{
		nil, {"export"},
		{"export", "--directory", "PRIVATE", "--from", "PRIVATE", "--to", "PRIVATE"},
		{"export", "--directory", "PRIVATE", "--from", "PRIVATE", "--to", "PRIVATE", "--consent", "PRIVATE"},
		{"export", "--directory", "PRIVATE", "--from", "PRIVATE", "--to", "PRIVATE", "--consent", "Metadata-only"},
		{"export", "--directory", "PRIVATE", "--from", "PRIVATE", "--to", "PRIVATE", "--to", "metadata-only"},
		{"export", "--directory", "PRIVATE", "--from", "PRIVATE", "--to", "PRIVATE", "--consent", "metadata-only", "extra"},
	} {
		err := auditExportArguments(context.Background(), args, read, export, io.Discard)
		if err == nil || reads != 0 || exports != 0 || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("missing consent read/exported or leaked values", err)
		}
	}
	valid := []string{"export", "--directory", "PRIVATE", "--from", "PRIVATE", "--to", "PRIVATE", "--consent", "metadata-only"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := auditExportArguments(ctx, valid, read, export, io.Discard); !errors.Is(err, context.Canceled) || reads != 0 || exports != 0 {
		t.Fatal("pre-canceled export read files", err)
	}
	if !audit.LocalRecordingSupported() {
		if err := auditExportArguments(context.Background(), valid, read, export, io.Discard); !errors.Is(err, audit.ErrLocalStorageUnsupported) || reads != 0 || exports != 0 {
			t.Fatal("unsupported exporter read files", err)
		}
	}
}
