package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
)

const auditUsage = "Audit verification and explicit local recording:\n" +
	"  accessweaver audit verify --events JSONL_FILE --from CHECKPOINT_FILE --to CHECKPOINT_FILE\n" +
	"  accessweaver audit initialize --directory EXISTING_PRIVATE_DIRECTORY\n" +
	"  accessweaver audit import --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --profile JSON_FILE\n" +
	"  accessweaver audit export --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --consent metadata-only\n" +
	"  accessweaver audit export-recorded --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --consent metadata-only\n" +
	"  accessweaver audit ui --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE\n" +
	"  accessweaver audit run --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --profile JSON_FILE --consent metadata-only\n" +
	"  accessweaver audit policy-install --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --input INSTALLATION.json --public-key BASE64\n" +
	"  accessweaver audit policy-update --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --input ENVELOPE.json\n" +
	"  accessweaver audit policy-rotate --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --input ROTATION.json\n" +
	"  accessweaver audit policy-recover --directory DIRECTORY --from GENESIS_FILE --to HEAD_FILE --input RECOVERY.json --public-key BASE64 --minimum-revision N\n" +
	"Local recording/export currently requires Linux amd64/arm64; verify is portable and read-only.\n" +
	"Export is a read-only snapshot. Export-recorded adds access intent/outcome; its checkpoints go to stderr, events to stdout. Neither supplies collector acknowledgment.\n" +
	"Run records one guarded foreground lifecycle: checkpoints to stdout, launch notice to stderr; clean process exit is not connectivity qualification.\n" +
	"Retain complete checkpoints through an independently trusted channel.\n" +
	"Self-selected checkpoints do not authenticate a producer or detect a rewritten history.\n" +
	"Audit import records reviewed imports; audit ui records profile saves/deletes and refuses other desktop actions. Explicit policy transactions are recorded; other administrator coverage and collectors remain incomplete.\n" +
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
	if len(args) > 0 && args[0] == "export-recorded" {
		return auditRecordedExportCommand(args, os.Stdout, os.Stderr)
	}
	if len(args) > 0 && recordedPolicyOperation(args[0]) != "" {
		return auditPolicyCommand(args, os.Stdout)
	}
	if len(args) > 0 && args[0] == "ui" {
		return auditUICommand(args, os.Stdout, os.Stderr)
	}
	if len(args) > 0 && args[0] == "run" {
		return auditRunCommand(args, os.Stdout, os.Stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	inputs := &auditInputSession{}
	result, err := verifyAuditArguments(ctx, args, inputs.read)
	if err != nil {
		return err
	}
	if err := checkAuditOutputAliases(ctx, []io.Writer{os.Stdout}, inputs.bindings, nil); err != nil {
		return errors.New("audit verification output unavailable or aliases an input")
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
// beyond the shared 15-second budget. Reads remain sequential: a timeout ends
// the command with at most one worker retaining its descriptor until OS return.
// That worker never writes or repairs an input and clears abandoned bytes.
type auditInputSnapshot struct {
	data    []byte
	binding auditInputBinding
}

type auditInputSession struct{ bindings []auditInputBinding }

func (s *auditInputSession) read(ctx context.Context, path string, limit int64) ([]byte, error) {
	snapshot, err := readAuditInputSnapshotUsing(ctx, func() (auditInputSnapshot, error) { return snapshotAuditInputBound(path, limit) })
	if err != nil {
		return nil, err
	}
	s.bindings = append(s.bindings, snapshot.binding)
	return snapshot.data, nil
}

func readAuditInput(ctx context.Context, path string, limit int64) ([]byte, error) {
	snapshot, err := readAuditInputSnapshotUsing(ctx, func() (auditInputSnapshot, error) { return snapshotAuditInputBound(path, limit) })
	return snapshot.data, err
}
func readAuditInputUsing(ctx context.Context, read func() ([]byte, error)) ([]byte, error) {
	snapshot, err := readAuditInputSnapshotUsing(ctx, func() (auditInputSnapshot, error) {
		data, err := read()
		return auditInputSnapshot{data: data}, err
	})
	return snapshot.data, err
}
func readAuditInputSnapshotUsing(ctx context.Context, read func() (auditInputSnapshot, error)) (auditInputSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return auditInputSnapshot{}, err
	}
	type result struct {
		snapshot auditInputSnapshot
		err      error
	}
	// No buffered late result can retain private bytes after caller cancellation.
	done := make(chan result)
	go func() {
		snapshot, err := read()
		select {
		case done <- result{snapshot, err}:
		case <-ctx.Done():
			clear(snapshot.data)
		}
	}()
	select {
	case <-ctx.Done():
		return auditInputSnapshot{}, ctx.Err()
	case r := <-done:
		if err := ctx.Err(); err != nil {
			clear(r.snapshot.data)
			return auditInputSnapshot{}, err
		}
		if r.err != nil {
			clear(r.snapshot.data)
			return auditInputSnapshot{}, r.err
		}
		return r.snapshot, nil
	}
}
func snapshotAuditInput(path string, limit int64) ([]byte, error) {
	snapshot, err := snapshotAuditInputBound(path, limit)
	return snapshot.data, err
}
func sameAuditInputState(a, b fileidentity.State) bool {
	return a.Kind == fileidentity.Regular && b.Kind == fileidentity.Regular && a.ID == b.ID && a.Size == b.Size && a.Modified.Equal(b.Modified)
}
func snapshotAuditInputBound(path string, limit int64) (snapshot auditInputSnapshot, failure error) {
	refuse := errors.New("audit input must be an unchanged bounded regular file")
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := fileidentity.FromPath(path, false)
	if err != nil || before.Kind != fileidentity.Regular || before.Size < 0 || before.Size > limit {
		return auditInputSnapshot{}, refuse
	}
	file, err := os.Open(path)
	if err != nil {
		return auditInputSnapshot{}, refuse
	}
	var payload []byte
	defer func() {
		if file.Close() != nil {
			failure = refuse
		}
		if failure != nil {
			clear(payload)
			snapshot = auditInputSnapshot{}
		}
	}()
	opened, err := fileidentity.FromFile(file)
	if err != nil || !sameAuditInputState(before, opened) {
		return auditInputSnapshot{}, refuse
	}
	payload, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(payload)) > limit || int64(len(payload)) != opened.Size {
		return auditInputSnapshot{}, refuse
	}
	after, err := fileidentity.FromFile(file)
	if err != nil || !sameAuditInputState(opened, after) {
		return auditInputSnapshot{}, refuse
	}
	named, err := fileidentity.FromPath(path, false)
	if err != nil || !sameAuditInputState(after, named) {
		return auditInputSnapshot{}, refuse
	}
	return auditInputSnapshot{data: payload, binding: auditInputBinding{path: path, state: after}}, nil
}
