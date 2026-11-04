//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/profile"
)

func auditedImportOutputFixture(t *testing.T) (string, string, []string, []string) {
	t.Helper()
	base, directory, from, to, _ := recordedExportNativeFixture(t)
	root := filepath.Join(base, "must-remain-absent")
	t.Setenv("ACCESSWEAVER_HOME", root)
	input := filepath.Join(base, "PRIVATE_PROFILE_INPUT.json")
	p := profile.New("audit-output-admission", "PRIVATE_PROFILE_NAME", "gost")
	p.Args = []string{"PRIVATE_PROFILE_TOKEN"}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	protected := []string{from, to, input, filepath.Join(directory, "events.journal"), filepath.Join(directory, ".actor-key")}
	args := []string{"import", "--directory", directory, "--from", from, "--to", to, "--profile", input}
	return base, root, protected, args
}

func snapshotImportOutputSources(t *testing.T, paths []string) [][]byte {
	t.Helper()
	before := make([][]byte, len(paths))
	for index, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("protected import fixture unavailable")
		}
		before[index] = data
	}
	t.Cleanup(func() {
		for _, data := range before {
			clear(data)
		}
	})
	return before
}

func assertImportOutputSourcesPreserved(t *testing.T, root string, paths []string, before [][]byte) {
	t.Helper()
	for index, path := range paths {
		after, err := os.ReadFile(path)
		same := bytes.Equal(before[index], after)
		clear(after)
		if err != nil || !same {
			t.Fatalf("output admission changed protected input %d", index)
		}
	}
	for _, path := range []string{root, filepath.Join(root, "profiles"), filepath.Join(root, ".controller.lock"), filepath.Join(root, ".profiles.lock")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("output admission created profile or controller storage")
		}
	}
}

// Keep the real dispatcher and its typed *os.File stdout boundary in scope.
// These tests deliberately do not run in parallel while replacing os.Stdout.
func executeAuditWithImportOutput(args []string, out *os.File) error {
	previous := os.Stdout
	os.Stdout = out
	defer func() { os.Stdout = previous }()
	return execute(append([]string{"audit"}, args...))
}

func TestAuditedImportOutputAliasesRefuseBeforeRecordingOrProfileCreation(t *testing.T) {
	for index, name := range []string{"from", "to", "profile", "journal", "key"} {
		for _, mode := range []string{"direct", "hard-link"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				base, root, protected, args := auditedImportOutputFixture(t)
				path := protected[index]
				if mode == "hard-link" {
					path = filepath.Join(base, "PRIVATE_OUTPUT_ALIAS")
					if err := os.Link(protected[index], path); err != nil {
						t.Fatal("hard-link output fixture unavailable")
					}
				}
				before := snapshotImportOutputSources(t, protected)
				// Append mode preserves every fixture byte before command admission;
				// unlike shell truncation, any added checkpoint would be attributable
				// to the command being tested.
				out, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal("append-mode output fixture unavailable")
				}
				commandErr := executeAuditWithImportOutput(args, out)
				closeErr := out.Close()
				if !errors.Is(commandErr, errAuditImportAdmission) || commandErr.Error() != errAuditImportAdmission.Error() || closeErr != nil {
					t.Fatal("output alias was not refused with the fixed admission error", commandErr)
				}
				assertImportOutputSourcesPreserved(t, root, protected, before)
			})
		}
	}
}

func TestAuditInitializeNilOutputPreservesEmptyDirectory(t *testing.T) {
	for _, mode := range []string{"interface", "dispatcher-typed-file"} {
		t.Run(mode, func(t *testing.T) {
			base := auditedImportDirectory(t)
			directory := filepath.Join(base, "audit")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "must-remain-absent")
			t.Setenv("ACCESSWEAVER_HOME", root)
			args := []string{"initialize", "--directory", directory}
			var err error
			if mode == "interface" {
				err = auditInitializeCommand(args, nil)
			} else {
				err = executeAuditWithImportOutput(args, nil)
			}
			if !errors.Is(err, errAuditInitializeAdmission) {
				t.Fatal("nil initialization output did not refuse before creation", err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatal("nil initialization output created journal or actor key")
			}
			assertImportOutputSourcesPreserved(t, root, nil, nil)
		})
	}
}

func TestAuditedImportNilOutputPreservesCurrentStream(t *testing.T) {
	for _, mode := range []string{"interface", "dispatcher-typed-file"} {
		t.Run(mode, func(t *testing.T) {
			_, root, protected, args := auditedImportOutputFixture(t)
			before := snapshotImportOutputSources(t, protected)
			var err error
			if mode == "interface" {
				err = auditImportCommand(args, nil)
			} else {
				err = executeAuditWithImportOutput(args, nil)
			}
			if !errors.Is(err, errAuditImportAdmission) {
				t.Fatal("nil import output did not refuse before recording", err)
			}
			assertImportOutputSourcesPreserved(t, root, protected, before)
		})
	}
}
