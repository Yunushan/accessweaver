//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// The existing hosted worker has already validated base and native revision 3.
// Use its approved inert ELF without native arguments or fixture environment:
// the real managed child environment must reach TestMain's clean exit.
func linuxRecordedManagedEngineProbe(t *testing.T, p profile.Profile, base string) {
	t.Helper()
	linuxNativeContext(t)
	if os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("recorded managed engine worker identity differs")
	}
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid || status.Revision != 3 || p.Engine != "byedpi" || filepath.Base(p.Binary) != "ciadpi" || len(p.Args) != 0 {
		t.Fatal("recorded managed engine fixture approval differs", err)
	}
	scope := filepath.Join(base, "recorded-engine")
	directory, root := filepath.Join(scope, "journal"), filepath.Join(scope, "state")
	if err := os.Mkdir(scope, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACCESSWEAVER_HOME", root)
	input := filepath.Join(scope, "profile.json")
	writeRecordedEngineProfile(t, input, p)
	preserved := map[string][]byte{}
	for _, path := range []string{input, "/etc/accessweaver/installation.json", "/etc/accessweaver/acceptance.json"} {
		preserved[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	checkPreserved := func() {
		t.Helper()
		for path, before := range preserved {
			now, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(now, before) {
				t.Fatal("recorded managed engine changed a protected fixture input", err)
			}
		}
		assertRecordedEngineNoInventory(t, root)
	}
	data, err := captureAuditExecute(t, []string{"initialize", "--directory", directory})
	if err != nil {
		t.Fatal("recorded managed engine journal initialization", err)
	}
	initialized := decodeCheckpointObservations(t, data)
	if len(initialized) != 1 || initialized[0].Sequence != 0 || initialized[0].Producer.ActorClass != "user" {
		t.Fatal("recorded managed engine genesis differs")
	}
	start := initialized[0]
	from, to := filepath.Join(scope, "genesis.json"), filepath.Join(scope, "head.json")
	writeRetainedCheckpoint(t, from, start)
	writeRetainedCheckpoint(t, to, start)
	keyPath := filepath.Join(directory, ".actor-key")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	preserved[keyPath] = key
	command := []string{"run", "--directory", directory, "--from", from, "--to", to, "--profile", input, "--consent", "metadata-only"}
	observed, notice, err := captureRecordedExportCLI(t, command)
	if err != nil || len(notice) == 0 {
		t.Fatal("approved recorded managed engine did not complete", err)
	}
	checkpoints := decodeCheckpointObservations(t, observed)
	if len(checkpoints) != 3 || checkpoints[0].Sequence != 1 || checkpoints[1].Sequence != 2 || checkpoints[2].Sequence != 3 {
		t.Fatal("recorded managed engine omitted intent, acceptance or terminal checkpoints")
	}
	events, end, raw := readRecordedEngineNativeEvents(t, directory, start)
	assertRecordedEngineNativeLifecycle(t, events, "completed")
	if end != checkpoints[2] {
		t.Fatal("recorded managed engine terminal checkpoint differs from its journal")
	}
	checkPreserved()
	journalPath := filepath.Join(directory, "events.journal")
	preserved[journalPath] = raw
	// The retained head still names genesis. This retry must fail before intent,
	// preparation or launch, while preserving the completed operation exactly.
	retry, retryNotice, err := captureRecordedExportCLI(t, command)
	if err == nil || len(retry) != 0 || len(retryNotice) != 0 {
		t.Fatal("recorded managed engine adopted a stale retained head")
	}
	checkPreserved()
	writeRetainedCheckpoint(t, to, checkpoints[2])
	exported, err := captureAuditExecute(t, []string{"export", "--directory", directory, "--from", from, "--to", to, "--consent", "metadata-only"})
	if err != nil {
		t.Fatal("recorded managed engine metadata export", err)
	}
	verified, err := audit.VerifySegment(context.Background(), bytes.NewReader(exported), start, checkpoints[2])
	if err != nil || verified.Records != 3 {
		t.Fatal("recorded managed engine full segment did not verify", err)
	}
	for _, private := range [][]byte{[]byte(p.ID), []byte(p.Name), []byte(p.Binary), []byte(base), preserved[input], key} {
		for _, output := range [][]byte{observed, notice, raw, exported} {
			if len(private) != 0 && bytes.Contains(output, private) {
				t.Fatal("private managed engine input escaped metadata output")
			}
		}
	}
	journal, err := audit.OpenLocalJournal(context.Background(), directory, start, checkpoints[2])
	if err != nil {
		t.Fatal("recorded managed engine retained its journal writer", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err := filelock.TryAcquire(filepath.Join(root, ".controller.lock"))
	if err != nil {
		t.Fatal("recorded managed engine retained controller ownership", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	// This remains a valid profile, but its changed execution digest is absent
	// from the fixed native policy. Preview must refuse before any new intent.
	unapproved := p
	unapproved.Routing.IncludeDomains = []string{"example.invalid"}
	writeRecordedEngineProfile(t, input, unapproved)
	preserved[input], err = os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	refused, refusedNotice, err := captureRecordedExportCLI(t, command)
	if !errors.Is(err, errAuditRunPreview) || len(refused) != 0 || len(refusedNotice) != 0 {
		t.Fatal("unapproved recorded managed engine reached dispatch", err)
	}
	checkPreserved()
	if _, err := os.Lstat(filepath.Join(root, "generated")); !os.IsNotExist(err) {
		t.Fatal("unapproved recorded managed engine prepared generated inputs", err)
	}
}

// The earlier native case must first prove that an appended byte denies launch.
// Restore only that exact root-owned fixture inode, retaining its original
// permissions and signed hash for the later ordinary-user recorded run.
func restoreLinuxRecordedEngineFixture(t *testing.T, fixtureRoot, path string, originalInfo os.FileInfo, original []byte) {
	t.Helper()
	linuxNativeContext(t)
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 ||
		filepath.Dir(fixtureRoot) != "/etc" || !strings.HasPrefix(filepath.Base(fixtureRoot), "accessweaver-policy-test-") ||
		path != filepath.Join(fixtureRoot, "payload", "ciadpi") {
		t.Fatal("refusing unrelated managed engine fixture restoration")
	}
	protected := func(info os.FileInfo) bool {
		if info == nil || !info.Mode().IsRegular() || info.Mode() != 0755 {
			return false
		}
		native, ok := info.Sys().(*syscall.Stat_t)
		return ok && native.Uid == 0 && native.Gid == 0 && native.Nlink == 1
	}
	named, err := os.Lstat(path)
	if err != nil || !protected(originalInfo) || !protected(named) || !os.SameFile(originalInfo, named) {
		t.Fatal("refusing changed managed engine fixture restoration", err)
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	opened, err := file.Stat()
	if err != nil || !protected(opened) || !os.SameFile(originalInfo, opened) {
		t.Fatal("managed engine fixture identity changed on restoration", err)
	}
	tampered, err := io.ReadAll(io.NewSectionReader(file, 0, int64(len(original)+2)))
	if err != nil || len(tampered) != len(original)+1 || tampered[len(original)] != 0 || !bytes.Equal(tampered[:len(original)], original) {
		t.Fatal("refusing unexpected managed engine fixture bytes", err)
	}
	// Only remove the exact deliberately appended byte; never replace an inode
	// or rewrite an unexpected file while running this hosted root setup.
	if err := file.Truncate(int64(len(original))); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	restored, err := file.Stat()
	current, namedErr := os.Lstat(path)
	if err != nil || namedErr != nil || !protected(restored) || !protected(current) || !os.SameFile(originalInfo, restored) || !os.SameFile(restored, current) || restored.Size() != int64(len(original)) {
		t.Fatal("restored managed engine fixture identity differs", err, namedErr)
	}
}
