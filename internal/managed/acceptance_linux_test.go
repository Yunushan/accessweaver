//go:build linux && (amd64 || arm64)

package managed

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
)

const acceptanceFixtureFile = "acceptance.json"

func writeAcceptanceFixture(t *testing.T, parent, name string, source []byte, now time.Time) {
	t.Helper()
	record, err := prepareAcceptance(source, now)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for leaf, data := range map[string][]byte{linuxPolicyFile: source, acceptanceFixtureFile: record} {
		if err := os.WriteFile(filepath.Join(dir, leaf), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func openAcceptanceFixture(t *testing.T, parent *os.File, name string) *os.File {
	t.Helper()
	dir, err := linuxtrust.OpenDirectoryAt(parent, name, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dir.Close(); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func readAcceptanceFixture(t *testing.T, dir *os.File) ([]byte, *acceptedHistory) {
	t.Helper()
	source, err := readLinuxInstallation(dir, uint32(os.Geteuid()), false)
	if err != nil {
		t.Fatal(err)
	}
	file, err := linuxtrust.OpenRegularAt(dir, acceptanceFixtureFile, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	record, readErr := io.ReadAll(io.LimitReader(file, maxAcceptanceBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(readErr, closeErr)
	}
	accepted, err := readAcceptance(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := accepted.checkSource(source); err != nil {
		t.Fatal("mixed source/acceptance fixture", err)
	}
	return source, accepted
}

func TestLinuxAcceptanceExchangePublishesBothRecords(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	candidate, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeAcceptanceFixture(t, root, linuxPolicyDirectory, prior, now)
	writeAcceptanceFixture(t, root, "candidate", candidate, now)
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	before := openAcceptanceFixture(t, parent, linuxPolicyDirectory)
	if err := exchangeLinuxDirectories(parent, "candidate", linuxPolicyDirectory); err != nil {
		t.Fatal(err)
	}
	// Open directory descriptors remain on their original complete generation.
	// A future native reader must retry if cleanup races before its files open.
	old, oldHistory := readAcceptanceFixture(t, before)
	current, newHistory := readAcceptanceFixture(t, openAcceptanceFixture(t, parent, linuxPolicyDirectory))
	displaced, displacedHistory := readAcceptanceFixture(t, openAcceptanceFixture(t, parent, "candidate"))
	if !bytes.Equal(old, prior) || oldHistory.revision != 2 || !bytes.Equal(displaced, prior) || displacedHistory.revision != 2 || !bytes.Equal(current, candidate) || newHistory.revision != 3 {
		t.Fatal("exchange mixed policy generations")
	}
	if err := parent.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxAcceptancePrimaryOnlyRestoreIsDetected(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	candidate, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeAcceptanceFixture(t, root, linuxPolicyDirectory, candidate, now)
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	dir := openAcceptanceFixture(t, parent, linuxPolicyDirectory)
	_, accepted := readAcceptanceFixture(t, dir)
	if err := os.WriteFile(filepath.Join(root, linuxPolicyDirectory, linuxPolicyFile), prior, 0644); err != nil {
		t.Fatal(err)
	}
	restored, err := readLinuxInstallation(dir, uint32(os.Geteuid()), false)
	if err != nil {
		t.Fatal(err)
	}
	// The legacy decoder alone has no independent counter. Native integration
	// must enforce the separate acceptance check before returning authority.
	authority, err := DecodeInstallation(restored, now)
	if err != nil || authority.verified.Policy.Revision != 2 {
		t.Fatal("legacy rollback diagnostic setup failed", err)
	}
	if !errors.Is(accepted.checkSource(restored), ErrUnavailable) {
		t.Fatal("restored signed source matched the newer acceptance record")
	}
}

func TestLinuxAcceptanceExchangeFailurePreservesCurrentPair(t *testing.T) {
	prior, _, _, _, now := renewalFixture(t)
	root := t.TempDir()
	writeAcceptanceFixture(t, root, linuxPolicyDirectory, prior, now)
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := exchangeLinuxDirectories(parent, "missing", linuxPolicyDirectory); err == nil {
		t.Fatal("missing candidate exchanged")
	}
	current, accepted := readAcceptanceFixture(t, openAcceptanceFixture(t, parent, linuxPolicyDirectory))
	if !bytes.Equal(current, prior) || accepted.revision != 2 {
		t.Fatal("failed exchange changed current state")
	}
}

func TestLinuxAcceptanceExchangePreservesUnrelatedContents(t *testing.T) {
	prior, next, _, _, now := renewalFixture(t)
	candidate, _, err := installationTransition(prior, next, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeAcceptanceFixture(t, root, linuxPolicyDirectory, prior, now)
	writeAcceptanceFixture(t, root, "candidate", candidate, now)
	sentinel := []byte("unrelated contents require explicit preservation")
	if err := os.WriteFile(filepath.Join(root, linuxPolicyDirectory, "unrelated"), sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := exchangeLinuxDirectories(parent, "candidate", linuxPolicyDirectory); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(filepath.Join(root, "candidate", "unrelated"))
	if err != nil || !bytes.Equal(retained, sentinel) {
		t.Fatal("exchange deleted unrelated data", err)
	}
	// A transaction must inspect this displaced directory and preserve unknown
	// entries during cleanup. The namespace primitive never removes any files.
}
