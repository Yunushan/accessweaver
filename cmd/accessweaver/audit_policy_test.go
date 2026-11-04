package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/managed"
)

func policyCommandArgs(operation string) []string {
	args := []string{"policy-" + operation, "--directory", "PRIVATE_DIRECTORY", "--from", "PRIVATE_FROM", "--to", "PRIVATE_TO", "--input", "PRIVATE_INPUT"}
	if operation == "install" || operation == "recover" {
		args = append(args, "--public-key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	}
	if operation == "recover" {
		args = append(args, "--minimum-revision", "4")
	}
	return args
}
func TestRecordedPolicyOptionsAreExactAndNeverAcceptPrivateKeysOrBackendSelection(t *testing.T) {
	for _, operation := range []string{"install", "update", "rotate", "recover"} {
		args := policyCommandArgs(operation)
		request, err := parseRecordedPolicyRequest(args)
		if err != nil || request.operation != operation || request.limit <= 0 || request.paths["--input"] != "PRIVATE_INPUT" {
			t.Fatal(operation, request, err)
		}
		for _, bad := range [][]string{args[:len(args)-1], append(append([]string{}, args...), "--private-key", "PRIVATE_SECRET"), append(append([]string{}, args...), "--root", "PRIVATE_MACHINE"), append(append([]string{}, args...), "--input", "DUPLICATE"), append(append([]string{}, args...), "--to", "DUPLICATE")} {
			if _, err := parseRecordedPolicyRequest(bad); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unsafe options or private error", operation, err)
			}
		}
	}
	for _, bad := range [][]string{nil, {"policy-remove"}, {"policy-install"}, {"managed-update"}} {
		if _, err := parseRecordedPolicyRequest(bad); err == nil {
			t.Fatal("unknown/incomplete options accepted")
		}
	}
	for _, floor := range []string{"0", "-1", "9007199254740992", "18446744073709551616", "PRIVATE_FLOOR"} {
		args := policyCommandArgs("recover")
		args[len(args)-1] = floor
		if _, err := parseRecordedPolicyRequest(args); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("unsafe recovery minimum", err)
		}
	}
	args := policyCommandArgs("install")
	args[len(args)-1] = "PRIVATE_KEY"
	if _, err := parseRecordedPolicyRequest(args); err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("invalid trust input exposed")
	}
}

func TestRecordedPolicyNativeOutcomeAndDurableAdmission(t *testing.T) {
	for _, operation := range []string{"install", "update", "rotate", "recover"} {
		for _, mode := range []string{"completed", "committed-error", "precommit-error", "missing-commit", "wrong-operation", "panic", "cancel-during", "cancel-before", "intent-write", "intent-output", "short-output", "result-write", "result-output", "capacity", "pre-canceled"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				j := newRecordedImportJournal(t)
				out := &importCheckpointWriter{}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch mode {
				case "intent-write":
					j.failAt = 1
				case "intent-output":
					out.failAt = 1
				case "short-output":
					out.failAt = 1
					out.short = true
				case "result-write":
					j.failAt = 2
				case "result-output":
					out.failAt = 2
				case "capacity":
					j.head.Sequence = audit.MaxSegmentRecords - 1
				case "pre-canceled":
					cancel()
				case "cancel-before":
					out.cancel = cancel
				}
				calls := 0
				err := executeRecordedPolicy(ctx, j, j.start, j.head, out, operation, func(recordedCtx context.Context) (managed.InstallResult, error) {
					calls++
					if len(j.events) != 1 || j.events[0].Outcome != "intent" || out.calls != 1 {
						t.Error("native dispatch preceded durable observed intent")
					}
					if audit.ProfileIntentActive(recordedCtx, "write") || audit.ProfileIntentActive(recordedCtx, "delete") {
						t.Error("policy producer granted profile authority")
					}
					result := managed.InstallResult{Operation: operation, Committed: true, KeyID: "PRIVATE_KEY", PayloadSHA256: "PRIVATE_PAYLOAD"}
					switch mode {
					case "committed-error":
						return result, errors.New("PRIVATE_PUBLISHED_OR_CLEANUP")
					case "precommit-error":
						result.Committed = false
						return result, errors.New("PRIVATE_NATIVE_ERROR")
					case "missing-commit":
						result.Committed = false
					case "wrong-operation":
						result.Operation = "other"
					case "panic":
						panic("PRIVATE_PANIC")
					case "cancel-during":
						cancel()
					}
					return result, nil
				})
				success := mode == "completed" || mode == "cancel-during"
				if (err == nil) != success || (err != nil && strings.Contains(err.Error(), "PRIVATE")) {
					t.Fatal("unsafe or inaccurate result", err)
				}
				noDispatch := mode == "cancel-before" || mode == "intent-write" || mode == "intent-output" || mode == "short-output" || mode == "capacity" || mode == "pre-canceled"
				if noDispatch && calls != 0 || !noDispatch && calls != 1 {
					t.Fatal("native invocation count", calls)
				}
				for _, event := range j.events {
					if event.Action != "policy."+operation {
						t.Fatal("wrong action", event)
					}
				}
				if success {
					if len(j.events) != 2 || j.events[1].Outcome != "completed" || j.events[0].OperationID != j.events[1].OperationID {
						t.Fatal("completed pair differs")
					}
				}
				if mode == "committed-error" || mode == "precommit-error" || mode == "missing-commit" || mode == "wrong-operation" || mode == "panic" {
					if !errors.Is(err, audit.ErrRecordedUncertain) || len(j.events) != 2 || j.events[1].Outcome != "indeterminate" {
						t.Fatal("native uncertainty erased", err, j.events)
					}
				}
				if mode == "cancel-before" && (len(j.events) != 2 || j.events[1].Outcome != "canceled") {
					t.Fatal("undispatched cancellation differs")
				}
				if mode == "result-write" || mode == "result-output" {
					if !errors.Is(err, audit.ErrRecordedUncertain) {
						t.Fatal("post-operation loss not uncertain", err)
					}
				}
				if mode != "capacity" {
					if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(bytes.Join(j.lines, nil)), j.start, j.head); err != nil {
						t.Fatal("actual chain does not verify", err)
					}
				}
				if bytes.Contains(out.Bytes(), []byte("PRIVATE")) || bytes.Contains(bytes.Join(j.lines, nil), []byte("PRIVATE")) {
					t.Fatal("native data escaped metadata")
				}
			})
		}
	}
	j := newRecordedImportJournal(t)
	for _, operation := range []string{"", "remove", "profile.write", "install/../update"} {
		err := executeRecordedPolicy(context.Background(), j, j.start, j.head, &bytes.Buffer{}, operation, func(context.Context) (managed.InstallResult, error) {
			t.Error("unsupported operation dispatched")
			return managed.InstallResult{}, nil
		})
		if !errors.Is(err, audit.ErrRecorderUnavailable) || j.calls != 0 {
			t.Fatal("unsupported producer admitted")
		}
	}
}

func TestRecordedPolicyCheckpointOutputCannotAliasProtectedInputs(t *testing.T) {
	root := t.TempDir()
	paths := []string{}
	for _, leaf := range []string{"from", "to", "input", "journal", "key", "machine-source", "acceptance", "coordination"} {
		path := filepath.Join(root, leaf)
		if err := os.WriteFile(path, []byte("PRESERVE_PRIVATE_BYTES"), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	for _, path := range paths {
		out, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		err = checkRecordedPolicyOutput(out, paths[:5], paths[5:])
		out.Close()
		if !errors.Is(err, errAuditPolicyOutput) {
			t.Fatal("direct output alias accepted", err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "PRESERVE_PRIVATE_BYTES" {
			t.Fatal("alias check changed input")
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Link(paths[0], alias); err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(alias, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRecordedPolicyOutput(out, paths[:5], paths[5:]); err == nil {
		t.Fatal("hard-link alias accepted")
	}
	out.Close()
	out, err = os.CreateTemp(root, "observation")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := checkRecordedPolicyOutput(out, paths[:5], append(paths[5:], filepath.Join(root, "absent"))); err != nil {
		t.Fatal("separate output denied", err)
	}
	if err := checkRecordedPolicyOutput(out, append(append([]string{}, paths[:5]...), filepath.Join(root, "required-missing")), nil); err == nil {
		t.Fatal("missing required binding accepted")
	}
	out.Close()
	if err := checkRecordedPolicyOutput(out, paths, nil); err == nil {
		t.Fatal("closed output accepted")
	}
}
