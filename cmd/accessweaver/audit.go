package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
)

const auditUsage = "Audit verification and explicit local recording:\n" +
	"  accessweaver audit verify --events JSONL_FILE --from CHECKPOINT_FILE --to CHECKPOINT_FILE\n" +
	"  accessweaver audit initialize --directory EXISTING_PRIVATE_DIRECTORY\n" +
	"  accessweaver audit import --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --profile JSON_FILE\n" +
	"  accessweaver audit export --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --consent metadata-only\n" +
	"  accessweaver audit ui --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE\n" +
	"Local recording/export currently requires Linux amd64/arm64; verify is portable and read-only.\n" +
	"Export is a read-only snapshot; separate export-access recording and collector acknowledgments remain incomplete.\n" +
	"Retain complete checkpoints through an independently trusted channel.\n" +
	"Self-selected checkpoints do not authenticate a producer or detect a rewritten history.\n" +
	"Audit import records reviewed imports; audit ui records profile saves/deletes and refuses other desktop actions. Administrator coverage and collectors remain incomplete.\n" +
	"See docs/AUDIT_EVENTS.md for the format, limits and remaining integration work.\n"

func auditCommand(args []string) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		_, err := fmt.Fprint(os.Stdout, auditUsage)
		if err != nil {
			return errors.New("audit help output unavailable")
		}
		return nil
	}
	if len(args) > 0 && args[0] == "initialize" {
		return auditInitializeCommand(args, os.Stdout)
	}
	if len(args) > 0 && args[0] == "import" {
		return auditImportCommand(args, os.Stdout)
	}
	if len(args) > 0 && args[0] == "export" {
		return auditExportCommand(args, os.Stdout)
	}
	if len(args) > 0 && args[0] == "ui" {
		return auditUICommand(args, os.Stdout, os.Stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := verifyAuditArguments(ctx, args, readAuditInput)
	if err != nil {
		return err
	}
	if err := printJSON(result); err != nil {
		return errors.New("audit verification output unavailable")
	}
	return nil
}

type auditInputReader func(context.Context, string, int64) ([]byte, error)

func verifyAuditArguments(ctx context.Context, args []string, read auditInputReader) (audit.Verification, error) {
	zero := audit.Verification{}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if len(args) != 7 || args[0] != "verify" {
		return zero, errors.New("usage: accessweaver audit verify --events FILE --from FILE --to FILE")
	}
	paths := map[string]string{}
	for i := 1; i < len(args); i += 2 {
		key := args[i]
		if key != "--events" && key != "--from" && key != "--to" || paths[key] != "" || args[i+1] == "" {
			return zero, errors.New("audit verification requires exactly one events file and two checkpoint files")
		}
		paths[key] = args[i+1]
	}
	fromData, err := read(ctx, paths["--from"], audit.MaxCheckpointBytes)
	if err != nil {
		return zero, err
	}
	from, err := audit.DecodeCheckpoint(fromData)
	if err != nil {
		return zero, err
	}
	toData, err := read(ctx, paths["--to"], audit.MaxCheckpointBytes)
	if err != nil {
		return zero, err
	}
	to, err := audit.DecodeCheckpoint(toData)
	if err != nil {
		return zero, err
	}
	data, err := read(ctx, paths["--events"], audit.MaxSegmentBytes)
	if err != nil {
		return zero, err
	}
	return audit.VerifySegment(ctx, bytes.NewReader(data), from, to)
}

// Each read runs in one worker so a blocked filesystem cannot hold the CLI
// beyond the shared 15-second input/verification budget. Reads are sequential: a timeout
// ends the command, leaving at most one outstanding worker until process exit.
// The worker owns its descriptor and never writes or repairs an input.
func readAuditInput(ctx context.Context, path string, limit int64) ([]byte, error) {
	return readAuditInputUsing(ctx, func() ([]byte, error) { return snapshotAuditInput(path, limit) })
}
func readAuditInputUsing(ctx context.Context, read func() ([]byte, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() { data, err := read(); done <- result{data, err} }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return r.data, r.err
	}
}
func snapshotAuditInput(path string, limit int64) (data []byte, failure error) {
	refuse := errors.New("audit input must be an unchanged bounded regular file")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, refuse
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, refuse
	}
	defer func() {
		if file.Close() != nil {
			data = nil
			failure = refuse
		}
	}()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		return nil, refuse
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit || int64(len(data)) != opened.Size() {
		return nil, refuse
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, refuse
	}
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(after, named) || named.Size() != after.Size() || !named.ModTime().Equal(after.ModTime()) {
		return nil, refuse
	}
	return data, nil
}
