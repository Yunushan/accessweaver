package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/managed"
)

var errAuditPolicyInput = errors.New("invalid recorded policy options; use audit help and independently reviewed public trust inputs")
var errAuditPolicyOutput = errors.New("policy checkpoint output must be separate from its inputs, journal, actor key and machine authority")

type recordedPolicyRequest struct {
	operation string
	paths     map[string]string
	public    ed25519.PublicKey
	minimum   uint64
	limit     int64
}

func recordedPolicyOperation(command string) string {
	switch command {
	case "policy-install":
		return "install"
	case "policy-update":
		return "update"
	case "policy-rotate":
		return "rotate"
	case "policy-recover":
		return "recover"
	}
	return ""
}
func parseRecordedPolicyRequest(args []string) (recordedPolicyRequest, error) {
	var request recordedPolicyRequest
	if len(args) == 0 {
		return request, errAuditPolicyInput
	}
	request.operation = recordedPolicyOperation(args[0])
	keys := []string{"--directory", "--from", "--to", "--input"}
	switch request.operation {
	case "install":
		request.limit = managed.MaxInstallationBytes
		keys = append(keys, "--public-key")
	case "update":
		request.limit = managed.MaxEnvelopeBytes
	case "rotate":
		request.limit = managed.MaxRotationBytes
	case "recover":
		request.limit = managed.MaxRecoveryBytes
		keys = append(keys, "--public-key", "--minimum-revision")
	default:
		return request, errAuditPolicyInput
	}
	var err error
	request.paths, err = auditPaths(args, args[0], keys...)
	if err != nil {
		return recordedPolicyRequest{}, errAuditPolicyInput
	}
	if request.operation == "install" || request.operation == "recover" {
		request.public, err = managed.PublicKey(request.paths["--public-key"])
		if err != nil {
			return recordedPolicyRequest{}, errAuditPolicyInput
		}
	}
	if request.operation == "recover" {
		request.minimum, err = strconv.ParseUint(request.paths["--minimum-revision"], 10, 64)
		if err != nil || request.minimum == 0 || request.minimum > 1<<53-1 {
			return recordedPolicyRequest{}, errAuditPolicyInput
		}
	}
	return request, nil
}

// Native authority is selected only by these production entry points. Neither
// arguments, the user data root nor the journal can replace a native backend.
func (request recordedPolicyRequest) apply(data []byte) (managed.InstallResult, error) {
	switch request.operation {
	case "install":
		return managed.Install(data, request.public)
	case "update":
		return managed.Update(data)
	case "rotate":
		return managed.Rotate(data)
	case "recover":
		return managed.Recover(data, request.public, request.minimum)
	}
	return managed.InstallResult{}, errAuditPolicyInput
}

func auditPolicyCommand(args []string, out io.Writer) (failure error) {
	request, err := parseRecordedPolicyRequest(args)
	if err != nil {
		return err
	}
	// The fixed-authority output checks below are Linux-specific. New local
	// storage backends must supply their own authority binding checks first.
	if runtime.GOOS != "linux" || !audit.LocalRecordingSupported() {
		return audit.ErrLocalStorageUnsupported
	}
	if out == nil {
		return errAuditPolicyOutput
	}
	directory := request.paths["--directory"]
	if directory == "/etc/accessweaver" || strings.HasPrefix(directory, "/etc/accessweaver/") {
		return errAuditPolicyInput
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	inputCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	decode := func(path string) (audit.Checkpoint, error) {
		data, err := readAuditInput(inputCtx, path, audit.MaxCheckpointBytes)
		if err != nil {
			return audit.Checkpoint{}, err
		}
		return audit.DecodeCheckpoint(data)
	}
	from, err := decode(request.paths["--from"])
	if err != nil {
		return err
	}
	to, err := decode(request.paths["--to"])
	if err != nil {
		return err
	}
	data, err := readAuditInput(inputCtx, request.paths["--input"], request.limit)
	if err != nil {
		return err
	}
	defer clear(data)
	required := []string{request.paths["--from"], request.paths["--to"], request.paths["--input"], filepath.Join(directory, "events.journal"), filepath.Join(directory, ".actor-key")}
	optional := []string{"/etc/accessweaver/installation.json", "/etc/accessweaver/acceptance.json", "/etc/.accessweaver-policy.lock"}
	if err := checkRecordedPolicyOutput(out, required, optional); err != nil {
		return err
	}
	journal, err := audit.OpenLocalJournal(inputCtx, directory, from, to)
	if err != nil {
		return err
	}
	defer func() {
		if journal.Close() != nil {
			failure = audit.ErrRecordedUncertain
		}
	}()
	if err := inputCtx.Err(); err != nil {
		return err
	}
	cancel() // Do not abandon a native publication when the input budget ends.
	return executeRecordedPolicy(ctx, journal, from, to, out, request.operation, func(context.Context) (managed.InstallResult, error) { return request.apply(data) })
}

// The command owns this exclusively locked journal and closes it after this
// synchronous borrowed recorder scope returns. No callback/recorder escapes.
func executeRecordedPolicy(ctx context.Context, journal audit.LocalJournal, from, to audit.Checkpoint, out io.Writer, operation string, apply func(context.Context) (managed.InstallResult, error)) error {
	if recordedPolicyOperation("policy-"+operation) == "" || apply == nil {
		return audit.ErrRecorderUnavailable
	}
	recorder, err := audit.NewRecorder(ctx, journal, from, to, out)
	if err != nil {
		return audit.ErrRecorderUnavailable
	}
	return recorder.Execute(ctx, "policy."+operation, func(recordedCtx context.Context) audit.OperationResult {
		if err := recordedCtx.Err(); err != nil {
			return audit.OperationResult{Outcome: "canceled", Err: context.Canceled}
		}
		result, err := apply(recordedCtx)
		// A native error can follow publication or cleanup. Committed=false is not
		// proof that nothing changed, and success without a matching committed
		// result is not completion. Preserve all uncertainty without private errors.
		if err != nil || !result.Committed || result.Operation != operation {
			return audit.OperationResult{Outcome: "indeterminate", Err: audit.ErrRecordedUncertain}
		}
		return audit.OperationResult{Outcome: "completed"}
	})
}

func checkRecordedPolicyOutput(out io.Writer, required, optional []string) error {
	file, ok := out.(*os.File)
	if !ok {
		return nil
	} // Pipe/writer forwarding is the caller's responsibility.
	info, err := file.Stat()
	if err != nil {
		return errAuditPolicyOutput
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	for index, path := range append(append([]string{}, required...), optional...) {
		input, err := os.Stat(path)
		if err != nil {
			if index >= len(required) && os.IsNotExist(err) {
				continue
			}
			return errAuditPolicyOutput
		}
		if os.SameFile(info, input) {
			return errAuditPolicyOutput
		}
	}
	return nil
}
