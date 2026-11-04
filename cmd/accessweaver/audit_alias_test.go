package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
)

type auditAliasWriteSpy struct{ writes int }

func (writer *auditAliasWriteSpy) Write([]byte) (int, error) {
	writer.writes++
	return 0, errors.New("metadata guard attempted a write")
}

func TestAuditOutputAliasesNilWritersAndCancellation(t *testing.T) {
	var nilFile *os.File
	var nilOpaque *auditAliasWriteSpy
	for _, writer := range []io.Writer{nil, nilFile, nilOpaque} {
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{writer}, nil, nil); err != errAuditOutputAlias {
			t.Fatal("nil writer did not return the fixed refusal", err)
		}
		if !auditWriterUnavailable(writer) {
			t.Fatal("early writer admission accepted a nil writer")
		}
	}
	writer := &auditAliasWriteSpy{}
	if auditWriterUnavailable(writer) {
		t.Fatal("early writer admission rejected a nonnil opaque writer")
	}
	if err := checkAuditOutputAliases(context.Background(), []io.Writer{writer}, nil, nil); err != nil || writer.writes != 0 {
		t.Fatal("opaque writer was probed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkAuditOutputAliases(ctx, []io.Writer{writer}, nil, nil); err != context.Canceled || writer.writes != 0 {
		t.Fatal("canceled guard did not stop without output", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	if err := checkAuditOutputAliases(deadline, []io.Writer{writer}, nil, nil); err != context.DeadlineExceeded {
		t.Fatal("expired guard did not retain context failure", err)
	}
	if err := checkAuditOutputAliases(nil, []io.Writer{writer}, nil, nil); err != errAuditOutputAlias {
		t.Fatal("nil context did not return a fixed refusal", err)
	}
}

func TestAuditOutputAliasesMetadata(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd":
		runAuditAliasMetadataTests(t)
	case "windows":
		t.Skip("Windows metadata fixtures use TestWindowsAuditAliasMetadata with explicit hosted opt-in")
	default:
		t.Skip("native file identity metadata is unavailable on this platform")
	}
}

func TestWindowsAuditAliasMetadata(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows hosted metadata qualification only")
	}
	if _, present := os.LookupEnv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST"); !present {
		t.Skip("requires explicit disposable Windows audit storage opt-in")
	}
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Fatal("opted-in alias fixture requires declared GitHub-hosted Windows context")
	}
	arch := runtime.GOARCH
	if (arch != "amd64" && arch != "arm64") || os.Getenv("ACCESSWEAVER_EXPECT_GOOS") != "windows" || os.Getenv("ACCESSWEAVER_EXPECT_GOARCH") != arch || os.Getenv("RUNNER_ARCH") != map[string]string{"amd64": "X64", "arm64": "ARM64"}[arch] {
		t.Fatal("opted-in alias fixture requires its declared native AMD64 or ARM64 target")
	}
	t.Cleanup(func() { retainAuditNativeReceipt(t, "alias", "source-built-native-audit-output-aliases") })
	runAuditAliasMetadataTests(t)
}

func auditAliasFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal("metadata fixture file unavailable")
	}
	return path
}

func auditAliasBinding(t *testing.T, path string) auditInputBinding {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("source snapshot handle unavailable")
	}
	state, queryErr := fileidentity.FromFile(file)
	closeErr := file.Close()
	if queryErr != nil || closeErr != nil || state.Kind != fileidentity.Regular {
		t.Fatal("source snapshot metadata unavailable")
	}
	return auditInputBinding{path: path, state: state}
}

func auditAliasOutput(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal("append output fixture unavailable")
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func assertAuditAliasContents(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != expected {
		t.Fatal("metadata guard changed protected bytes")
	}
}

func assertAuditAliasRefused(t *testing.T, outputs []io.Writer, bindings []auditInputBinding, refs []auditPathReference) {
	t.Helper()
	if err := checkAuditOutputAliases(context.Background(), outputs, bindings, refs); err != errAuditOutputAlias {
		t.Fatal("guard did not return the fixed redacted refusal", err)
	}
}

func runAuditAliasMetadataTests(t *testing.T) {
	t.Run("bound-direct-and-hard-link", func(t *testing.T) {
		for _, hardLink := range []bool{false, true} {
			name := "direct"
			if hardLink {
				name = "hard-link"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				source := auditAliasFile(t, root, "PRIVATE_SOURCE", "PRESERVE_PRIVATE_SOURCE")
				other := auditAliasFile(t, root, "PRIVATE_OTHER", "OTHER_INPUT")
				bindings := []auditInputBinding{auditAliasBinding(t, other), auditAliasBinding(t, source)}
				target := source
				if hardLink {
					target = filepath.Join(root, "PRIVATE_OUTPUT_ALIAS")
					if err := os.Link(source, target); err != nil {
						t.Fatal("hard-link output fixture unavailable")
					}
				}
				out := auditAliasOutput(t, target)
				before, err := out.Seek(0, io.SeekCurrent)
				if err != nil {
					t.Fatal("borrowed output offset unavailable")
				}
				assertAuditAliasRefused(t, []io.Writer{out}, bindings, nil)
				if after, err := out.Seek(0, io.SeekCurrent); err != nil || after != before {
					t.Fatal("guard closed or moved its borrowed output handle")
				}
				assertAuditAliasContents(t, source, "PRESERVE_PRIVATE_SOURCE")
			})
		}
	})

	t.Run("retained-identity-after-name-replacement", func(t *testing.T) {
		root := t.TempDir()
		source := auditAliasFile(t, root, "PRIVATE_SOURCE", "ORIGINAL_SOURCE")
		binding := auditAliasBinding(t, source)
		retained := filepath.Join(root, "PRIVATE_RETAINED_OLD_IDENTITY")
		if err := os.Link(source, retained); err != nil {
			t.Fatal("retained original identity fixture unavailable")
		}
		replacement := auditAliasFile(t, root, "PRIVATE_REPLACEMENT", "NEW_SOURCE_DATA")
		if err := os.Chtimes(replacement, binding.state.Modified, binding.state.Modified); err != nil {
			t.Fatal("replacement metadata fixture unavailable")
		}
		if err := os.Remove(source); err != nil {
			t.Fatal("original source name could not be replaced")
		}
		if err := os.Rename(replacement, source); err != nil {
			t.Fatal("replacement source name unavailable")
		}
		assertAuditAliasRefused(t, []io.Writer{auditAliasOutput(t, retained)}, []auditInputBinding{binding}, nil)
		// Even a nonalias opaque destination must reject the changed source name.
		spy := &auditAliasWriteSpy{}
		assertAuditAliasRefused(t, []io.Writer{spy}, []auditInputBinding{binding}, nil)
		if spy.writes != 0 {
			t.Fatal("changed binding emitted opaque output")
		}
		assertAuditAliasContents(t, retained, "ORIGINAL_SOURCE")
		assertAuditAliasContents(t, source, "NEW_SOURCE_DATA")
	})

	t.Run("pairwise-output-identities", func(t *testing.T) {
		root := t.TempDir()
		first := auditAliasFile(t, root, "PRIVATE_FIRST", "FIRST_OUTPUT")
		second := auditAliasFile(t, root, "PRIVATE_SECOND", "SECOND_OUTPUT")
		alias := filepath.Join(root, "PRIVATE_OUTPUT_ALIAS")
		if err := os.Link(first, alias); err != nil {
			t.Fatal("pairwise hard-link fixture unavailable")
		}
		one, same, hardLink, distinct := auditAliasOutput(t, first), auditAliasOutput(t, first), auditAliasOutput(t, alias), auditAliasOutput(t, second)
		assertAuditAliasRefused(t, []io.Writer{one, one}, nil, nil)
		assertAuditAliasRefused(t, []io.Writer{one, same}, nil, nil)
		assertAuditAliasRefused(t, []io.Writer{one, hardLink}, nil, nil)
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{one, distinct}, nil, nil); err != nil {
			t.Fatal("separate regular outputs refused", err)
		}
		assertAuditAliasContents(t, first, "FIRST_OUTPUT")
		assertAuditAliasContents(t, second, "SECOND_OUTPUT")
	})

	t.Run("binding-size-modified-and-absence", func(t *testing.T) {
		for _, change := range []string{"size", "modified", "absent"} {
			t.Run(change, func(t *testing.T) {
				root := t.TempDir()
				source := auditAliasFile(t, root, "PRIVATE_SOURCE", "ORIGINAL_SOURCE")
				binding := auditAliasBinding(t, source)
				switch change {
				case "size":
					if err := os.WriteFile(source, []byte("LONGER_CHANGED_SOURCE"), 0600); err != nil {
						t.Fatal("changed-size fixture unavailable")
					}
				case "modified":
					changed := binding.state.Modified.Add(2 * time.Second)
					if err := os.Chtimes(source, changed, changed); err != nil {
						t.Fatal("changed-modification fixture unavailable")
					}
				case "absent":
					if err := os.Remove(source); err != nil {
						t.Fatal("absent source fixture unavailable")
					}
				}
				spy := &auditAliasWriteSpy{}
				assertAuditAliasRefused(t, []io.Writer{spy}, []auditInputBinding{binding}, nil)
				if spy.writes != 0 {
					t.Fatal("source metadata refusal wrote output")
				}
			})
		}
	})

	t.Run("references-and-optional-absence", func(t *testing.T) {
		root := t.TempDir()
		source := auditAliasFile(t, root, "PRIVATE_REFERENCE", "REFERENCE_DATA")
		other := auditAliasFile(t, root, "PRIVATE_OUTPUT", "OUTPUT_DATA")
		refs := []auditPathReference{{path: source}}
		assertAuditAliasRefused(t, []io.Writer{auditAliasOutput(t, source)}, nil, refs)
		link := filepath.Join(root, "PRIVATE_HARD_LINK")
		if err := os.Link(source, link); err != nil {
			t.Fatal("reference hard-link fixture unavailable")
		}
		assertAuditAliasRefused(t, []io.Writer{auditAliasOutput(t, link)}, nil, refs)
		out := auditAliasOutput(t, other)
		absent := filepath.Join(root, "PRIVATE_ABSENT")
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{out}, nil, []auditPathReference{{path: absent, optional: true}}); err != nil {
			t.Fatal("genuinely absent optional reference was refused", err)
		}
		assertAuditAliasRefused(t, []io.Writer{out}, nil, []auditPathReference{{path: absent}})
		// An opaque destination still requires every reference to be available.
		spy := &auditAliasWriteSpy{}
		assertAuditAliasRefused(t, []io.Writer{spy}, nil, []auditPathReference{{path: absent}})
		assertAuditAliasRefused(t, []io.Writer{spy}, nil, []auditPathReference{{path: "\x00PRIVATE_INVALID", optional: true}})
		assertAuditAliasRefused(t, []io.Writer{spy}, nil, []auditPathReference{{path: root, optional: true}})
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{spy}, []auditInputBinding{auditAliasBinding(t, source)}, refs); err != nil || spy.writes != 0 {
			t.Fatal("valid opaque forwarding boundary was probed or refused", err)
		}
		assertAuditAliasContents(t, source, "REFERENCE_DATA")
		assertAuditAliasContents(t, other, "OUTPUT_DATA")
	})

	t.Run("explicit-leaf-link-policy", func(t *testing.T) {
		root := t.TempDir()
		source := auditAliasFile(t, root, "PRIVATE_TARGET", "TARGET_DATA")
		other := auditAliasFile(t, root, "PRIVATE_OUTPUT", "OUTPUT_DATA")
		link := filepath.Join(root, "PRIVATE_SYMBOLIC_LINK")
		if err := os.Symlink(source, link); err != nil {
			t.Fatal("explicit link-policy fixture unavailable")
		}
		out := auditAliasOutput(t, other)
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{out}, nil, []auditPathReference{{path: link, followLinks: true}}); err != nil {
			t.Fatal("explicitly followed regular reference was refused", err)
		}
		assertAuditAliasRefused(t, []io.Writer{out}, nil, []auditPathReference{{path: link}})
		assertAuditAliasRefused(t, []io.Writer{auditAliasOutput(t, source)}, nil, []auditPathReference{{path: link, followLinks: true}})
		binding := auditAliasBinding(t, source)
		binding.path = link
		assertAuditAliasRefused(t, []io.Writer{out}, []auditInputBinding{binding}, nil)
		dangling := filepath.Join(root, "PRIVATE_DANGLING_LINK")
		if err := os.Symlink(filepath.Join(root, "PRIVATE_ABSENT_TARGET"), dangling); err != nil {
			t.Fatal("dangling link-policy fixture unavailable")
		}
		assertAuditAliasRefused(t, []io.Writer{out}, nil, []auditPathReference{{path: dangling, optional: true}})
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{out}, nil, []auditPathReference{{path: dangling, followLinks: true, optional: true}}); err != nil {
			t.Fatal("explicitly followed absent optional target was refused", err)
		}
		assertAuditAliasContents(t, source, "TARGET_DATA")
		assertAuditAliasContents(t, other, "OUTPUT_DATA")
	})

	t.Run("unusable-output-and-borrowed-pipes", func(t *testing.T) {
		root := t.TempDir()
		path := auditAliasFile(t, root, "PRIVATE_OUTPUT", "OUTPUT_DATA")
		closed := auditAliasOutput(t, path)
		if err := closed.Close(); err != nil {
			t.Fatal("closed-output fixture unavailable")
		}
		assertAuditAliasRefused(t, []io.Writer{closed}, nil, nil)
		directory, err := os.Open(root)
		if err != nil {
			t.Fatal("directory-output fixture unavailable")
		}
		defer directory.Close()
		assertAuditAliasRefused(t, []io.Writer{directory}, nil, nil)
		readEnd, writeEnd, err := os.Pipe()
		if err != nil {
			t.Fatal("borrowed pipe fixture unavailable")
		}
		defer readEnd.Close()
		defer writeEnd.Close()
		if err := checkAuditOutputAliases(context.Background(), []io.Writer{writeEnd}, nil, nil); err != nil {
			t.Fatal("pipe output was refused", err)
		}
		// Stat succeeds only while the guard has kept the borrowed handle open.
		if _, err := writeEnd.Stat(); err != nil {
			t.Fatal("guard closed a borrowed pipe output")
		}
		assertAuditAliasContents(t, path, "OUTPUT_DATA")
	})
}
