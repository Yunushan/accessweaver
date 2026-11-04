package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
)

var errAuditExportConsent = errors.New("audit export requires explicit --consent metadata-only for actor, source, time and action metadata")

type auditSegmentExporter func(context.Context, string, audit.Checkpoint, audit.Checkpoint, io.Writer) error

// Consent and exact flags are checked before any input. The native exporter
// verifies a read-only snapshot and closes it before stdout receives bytes.
func auditExportArguments(ctx context.Context, args []string, read auditInputReader, export auditSegmentExporter, out io.Writer) error {
	paths, err := auditPaths(args, "export", "--directory", "--from", "--to", "--consent")
	if err != nil {
		return err
	}
	if paths["--consent"] != "metadata-only" {
		return errAuditExportConsent
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !audit.LocalRecordingSupported() {
		return audit.ErrLocalStorageUnsupported
	}
	decode := func(path string) (audit.Checkpoint, error) {
		data, err := read(ctx, path, audit.MaxCheckpointBytes)
		if err != nil {
			return audit.Checkpoint{}, err
		}
		return audit.DecodeCheckpoint(data)
	}
	from, err := decode(paths["--from"])
	if err != nil {
		return err
	}
	to, err := decode(paths["--to"])
	if err != nil {
		return err
	}
	if file, ok := out.(*os.File); ok {
		output, err := file.Stat()
		if err != nil {
			return audit.ErrExportOutput
		}
		if output.Mode().IsRegular() {
			for _, path := range []string{paths["--from"], paths["--to"]} {
				input, err := os.Stat(path)
				if err != nil {
					return errors.New("audit checkpoint input changed before export")
				}
				if os.SameFile(input, output) {
					return audit.ErrExportDestination
				}
			}
		}
	}
	return export(ctx, paths["--directory"], from, to, out)
}
func auditExportCommand(args []string, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return auditExportArguments(ctx, args, readAuditInput, audit.ExportLocalSegment, out)
}
