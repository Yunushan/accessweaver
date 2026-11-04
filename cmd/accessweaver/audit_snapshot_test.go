package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAuditInputSnapshotBindings(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd":
		runAuditInputSnapshotTests(t)
	default:
		t.Skip("native Windows input fixtures require explicit hosted opt-in")
	}
}
func runAuditInputSnapshotTests(t *testing.T) {
	t.Run("actual-read-retains-original-object", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "PRIVATE_INPUT")
		original, replacement := []byte("ORIGINAL_INPUT"), []byte("REPLACED_INPUT")
		if len(original) != len(replacement) {
			t.Fatal("replacement fixture length differs")
		}
		if os.WriteFile(path, original, 0600) != nil {
			t.Fatal("snapshot fixture unavailable")
		}
		inputs := &auditInputSession{}
		data, err := inputs.read(context.Background(), path, 128)
		if err != nil || !bytes.Equal(data, original) || len(inputs.bindings) != 1 {
			t.Fatal("actual read did not retain its native source")
		}
		defer clear(data)
		retained := filepath.Join(directory, "PRIVATE_RETAINED")
		if os.Rename(path, retained) != nil || os.WriteFile(path, replacement, 0600) != nil {
			t.Fatal("replacement fixture unavailable")
		}
		modified := inputs.bindings[0].state.Modified
		if os.Chtimes(path, modified, modified) != nil {
			t.Fatal("replacement timestamp fixture unavailable")
		}
		out := auditAliasOutput(t, retained)
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{out}, inputs.bindings, nil); err != errAuditOutputAlias {
			t.Fatal("source replacement hid old-object output alias")
		}
		spy := &auditAliasWriteSpy{}
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{spy}, inputs.bindings, nil); err != errAuditOutputAlias || spy.writes != 0 {
			t.Fatal("changed named input admitted output")
		}
		if got, err := os.ReadFile(retained); err != nil || !bytes.Equal(got, original) {
			t.Fatal("old source bytes changed")
		}
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, replacement) {
			t.Fatal("replacement source bytes changed")
		}
	})
	t.Run("verify-dispatcher-preserves-every-input-output-alias", func(t *testing.T) {
		for index, label := range []string{"from", "to", "events"} {
			for _, hardLink := range []bool{false, true} {
				name := label + "/direct"
				if hardLink {
					name = label + "/hard-link"
				}
				t.Run(name, func(t *testing.T) {
					args, files := auditCommandFixture(t)
					before := make([][]byte, len(files))
					for i, path := range files {
						var err error
						before[i], err = os.ReadFile(path)
						if err != nil {
							t.Fatal("verification fixture unavailable")
						}
					}
					target := files[index]
					if hardLink {
						target = filepath.Join(filepath.Dir(target), "PRIVATE_OUTPUT_ALIAS")
						if os.Link(files[index], target) != nil {
							t.Fatal("verification hardlink fixture unavailable")
						}
					}
					out := auditAliasOutput(t, target)
					previous := os.Stdout
					os.Stdout = out
					commandErr := func() error {
						defer func() { os.Stdout = previous }()
						return execute(append([]string{"audit"}, args...))
					}()
					if commandErr == nil {
						t.Fatal("read-only verification wrote into its input")
					}
					for i, path := range files {
						after, err := os.ReadFile(path)
						if err != nil || !bytes.Equal(after, before[i]) {
							t.Fatal("verification output changed an input")
						}
					}
				})
			}
		}
	})
}
