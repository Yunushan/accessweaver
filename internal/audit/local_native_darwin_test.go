//go:build darwin && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"golang.org/x/sys/unix"
)

type darwinLocalFixture struct {
	fixture *darwinAuditNativeFixture
	path    string
	start   Checkpoint
}

func newDarwinLocalFixture(t *testing.T, initialize bool) *darwinLocalFixture {
	t.Helper()
	owned := newDarwinAuditNativeFixture(t)
	fixture := &darwinLocalFixture{fixture: owned, path: owned.directory(t, owned.root, "stream")}
	if initialize {
		var err error
		fixture.start, err = initializeDarwinLocalJournal(fixture.path)
		if err != nil || fixture.start.Sequence != 0 || !validProducer(fixture.start.Producer) {
			t.Fatal("private native local initialization failed")
		}
	}
	return fixture
}
func (fixture *darwinLocalFixture) open(t *testing.T, head Checkpoint) *localDarwinJournal {
	t.Helper()
	raw, err := openDarwinLocalJournal(context.Background(), fixture.path, fixture.start, head)
	if err != nil || raw == nil {
		t.Fatal("private native current-process journal open failed")
	}
	local, ok := raw.(*localDarwinJournal)
	if !ok {
		raw.Close()
		t.Fatal("private native current-process adapter type differs")
	}
	t.Cleanup(func() {
		if !local.closed && local.Close() != nil {
			t.Error("private native local adapter cleanup failed")
		}
	})
	return local
}
func (fixture *darwinLocalFixture) probe(t *testing.T, head Checkpoint, expected byte) {
	t.Helper()
	journalFixture := &darwinJournalFixture{fixture: fixture.fixture, path: fixture.path, start: fixture.start}
	child := startDarwinJournalChild(t, journalFixture, head, "probe-exclusive")
	child.phase(t, expected)
	child.reap(t, false)
}

type darwinLocalObject struct {
	exists bool
	node   darwinAuditNativeNode
	data   []byte
	link   string
}

func darwinLocalCapture(t *testing.T, path string) darwinLocalObject {
	t.Helper()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return darwinLocalObject{}
	}
	if err != nil {
		t.Fatal("private native fixture object observation failed")
	}
	result := darwinLocalObject{exists: true, node: darwinAuditFixtureNode(t, path)}
	if info.Mode().IsRegular() {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("open bounded private fixture observation")
		}
		result.data, err = io.ReadAll(io.LimitReader(file, MaxJournalBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || len(result.data) > MaxJournalBytes {
			clear(result.data)
			t.Fatal("private fixture observation exceeded its bound")
		}
	} else if info.Mode()&os.ModeSymlink != 0 {
		result.link, err = os.Readlink(path)
		if err != nil {
			t.Fatal("observe owned key symlink fixture")
		}
	}
	return result
}
func darwinLocalPreserved(t *testing.T, path string, before darwinLocalObject) {
	t.Helper()
	after := darwinLocalCapture(t, path)
	defer clear(after.data)
	if after.exists != before.exists || after.node != before.node || after.link != before.link || !bytes.Equal(after.data, before.data) {
		t.Fatal("private native adapter refusal repaired or changed owned storage")
	}
}
func darwinLocalRewriteKey(t *testing.T, local *localDarwinJournal, directory string, payload []byte) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(directory, actorKeyName), os.O_RDWR, 0)
	if err != nil {
		t.Fatal("open exact owned key mutation fixture")
	}
	truncateErr := file.Truncate(int64(len(payload)))
	var commitErr error
	if truncateErr == nil {
		commitErr = commitJournalBytes(&darwinJournalCommitter{file: file, parent: local.dir.dir}, payload, 0)
	}
	closeErr := file.Close()
	if truncateErr != nil || commitErr != nil || closeErr != nil {
		t.Fatal("persist controlled owned key mutation fixture")
	}
}

func TestDarwinLocalNativeRoundTripAndExactCurrentProducer(t *testing.T) {
	fixture := newDarwinLocalFixture(t, true)
	keyPath, journalPath := filepath.Join(fixture.path, actorKeyName), filepath.Join(fixture.path, journalName)
	key := darwinLocalCapture(t, keyPath)
	defer clear(key.data)
	if len(key.data) != actorKeyFileBytes || !bytes.Equal(key.data[:len(actorKeyPrefix)], []byte(actorKeyPrefix)) || bytes.Equal(key.data[len(actorKeyPrefix):], make([]byte, 32)) {
		t.Fatal("private native actor key framing differs")
	}
	dir := darwinAuditOpenFixtureScope(t, fixture.path)
	retainedKey, err := readDarwinLocalActorKey(dir)
	if err != nil {
		t.Fatal("read private native framed actor key")
	}
	defer clear(retainedKey[:])
	expectedProducer, err := ProcessProducer(retainedKey)
	if err != nil || fixture.start.Producer != expectedProducer || expectedProducer.Target != "darwin/"+runtime.GOARCH || expectedProducer.ActorClass != "user" {
		t.Fatal("genesis did not bind the actual native process and build")
	}
	initial := darwinLocalCapture(t, journalPath)
	defer clear(initial.data)
	genesis, _ := EncodeCheckpoint(fixture.start)
	if !bytes.Equal(initial.data, genesis) {
		t.Fatal("private native initialization did not write exact genesis")
	}
	entries, err := os.ReadDir(fixture.path)
	if err != nil || len(entries) != 2 {
		t.Fatal("private local initialization created unexpected entries")
	}
	for _, name := range []string{actorKeyName, journalName} {
		file, err := dir.openRegular(name, false)
		if err != nil {
			t.Fatal("initialized native local object is not private")
		}
		state, stateErr := dir.fileState(file, name)
		closeErr := file.Close()
		if stateErr != nil || closeErr != nil || state.mode&07777 != 0600 || state.links != 1 || state.flags != 0 {
			t.Fatal("initialized native local object changed its private contract")
		}
	}
	local := fixture.open(t, fixture.start)
	line, expected, _ := Append(fixture.start, fixtureEvent(0))
	head, err := local.Append(context.Background(), fixtureEvent(0))
	if err != nil || head != expected {
		t.Fatal("private current-process append returned a different successor")
	}
	segment, from, to, err := local.Snapshot(context.Background())
	if err != nil || from != fixture.start || to != expected || !bytes.Equal(segment, line) {
		t.Fatal("private current-process snapshot changed exact endpoints")
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(segment), from, to); err != nil {
		t.Fatal("private current-process snapshot failed verification")
	}
	checkpointBytes, _ := EncodeCheckpoint(head)
	if bytes.Contains(segment, key.data) || bytes.Contains(segment, retainedKey[:]) || bytes.Contains(checkpointBytes, retainedKey[:]) || bytes.Contains(segment, []byte(fixture.path)) {
		t.Fatal("private key or fixture path entered returned evidence")
	}
	if other, err := openDarwinLocalJournal(context.Background(), fixture.path, fixture.start, expected); other != nil || !errors.Is(err, ErrJournalBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("private local adapter admitted another current writer")
	}
	fixture.probe(t, expected, darwinJournalChildBusy)
	owned := local.journal.file
	ancestors := append([]darwinAuditDirectoryBinding(nil), local.dir.ancestors...)
	if local.Close() != nil || local.Close() != nil {
		t.Fatal("private local adapter close is not healthy and idempotent")
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("private local adapter retained its owned journal file")
	}
	for _, binding := range ancestors {
		if _, err := binding.file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("private local adapter retained its owned directory scope")
		}
	}
	fixture.probe(t, expected, darwinJournalChildAvailable)
	if opened, err := openDarwinLocalJournal(context.Background(), fixture.path, fixture.start, fixture.start); opened != nil || err == nil {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("private local adapter adopted an unknown complete tail")
	}
	reopened := fixture.open(t, expected)
	again, _, end, err := reopened.Snapshot(context.Background())
	if err != nil || end != expected || !bytes.Equal(again, segment) || reopened.Close() != nil {
		t.Fatal("private current-process exact-head reopen failed")
	}
	darwinLocalPreserved(t, keyPath, key)
	if start, err := initializeDarwinLocalJournal(fixture.path); start != (Checkpoint{}) || err == nil {
		t.Fatal("private local reinitialization replaced an enrolled stream")
	}
	darwinLocalPreserved(t, keyPath, key)
}

func TestDarwinLocalNativeActorKeyFramingAndAliasesReturnZeroOnFailure(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "short", "oversize", "prefix", "zero", "mode", "read-acl", "flag", "symlink", "hardlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newDarwinLocalFixture(t, false)
			dir := darwinAuditOpenFixtureScope(t, fixture.path)
			keyPath := filepath.Join(fixture.path, actorKeyName)
			payload := append([]byte(actorKeyPrefix), bytes.Repeat([]byte{1}, 32)...)
			defer clear(payload)
			switch kind {
			case "missing":
			case "directory":
				fixture.fixture.directory(t, fixture.path, actorKeyName)
			case "fifo":
				if unix.Mkfifo(keyPath, 0600) != nil {
					t.Fatal("create owned actor-key FIFO fixture")
				}
			case "symlink", "hardlink":
				retained := filepath.Join(fixture.fixture.root, "retained-key")
				darwinAuditFreshFile(t, retained, payload)
				var err error
				if kind == "symlink" {
					err = os.Symlink("../retained-key", keyPath)
				} else {
					err = os.Link(retained, keyPath)
				}
				if err != nil {
					t.Fatal("create owned key-alias fixture")
				}
			default:
				data := payload
				switch kind {
				case "empty":
					data = nil
				case "short":
					data = payload[:len(payload)-1]
				case "oversize":
					data = append(bytes.Clone(payload), 0)
					defer clear(data)
				case "prefix":
					data = bytes.Clone(payload)
					data[0] ^= 1
					defer clear(data)
				case "zero":
					data = append([]byte(actorKeyPrefix), make([]byte, 32)...)
					defer clear(data)
				}
				darwinAuditFreshFile(t, keyPath, data)
				switch kind {
				case "mode":
					if os.Chmod(keyPath, 0640) != nil {
						t.Fatal("set owned key-mode fixture")
					}
				case "read-acl":
					darwinAuditFixtureACLCommand(t, keyPath, "+a", "everyone allow read,readattr,readextattr,readsecurity")
				case "flag":
					if unix.Chflags(keyPath, unix.UF_HIDDEN) != nil {
						t.Fatal("set owned key-flag fixture")
					}
				}
			}
			before := darwinLocalCapture(t, keyPath)
			defer clear(before.data)
			for attempt := 0; attempt < 2; attempt++ {
				key, err := readDarwinLocalActorKey(dir)
				if key != ([32]byte{}) || err == nil {
					clear(key[:])
					t.Fatal("invalid or aliased private actor key was returned")
				}
				if strings.Contains(err.Error(), fixture.path) {
					t.Fatal("actor-key refusal disclosed a private path")
				}
				darwinLocalPreserved(t, keyPath, before)
			}
		})
	}
}

func TestDarwinLocalNativePartialInitializationPreserved(t *testing.T) {
	for _, name := range []string{actorKeyName, journalName, "unrelated"} {
		t.Run(name, func(t *testing.T) {
			fixture := newDarwinLocalFixture(t, false)
			path := filepath.Join(fixture.path, name)
			darwinAuditFreshFile(t, path, []byte("preserve partial private initialization"))
			before := darwinLocalCapture(t, path)
			defer clear(before.data)
			for attempt := 0; attempt < 2; attempt++ {
				if start, err := initializeDarwinLocalJournal(fixture.path); start != (Checkpoint{}) || err == nil {
					t.Fatal("partial or nonempty private initialization admitted")
				}
				darwinLocalPreserved(t, path, before)
				entries, err := os.ReadDir(fixture.path)
				if err != nil || len(entries) != 1 || entries[0].Name() != name {
					t.Fatal("partial initialization was repaired or augmented")
				}
			}
		})
	}
	fixture := newDarwinLocalFixture(t, false)
	missing := filepath.Join(fixture.path, "missing")
	if start, err := initializeDarwinLocalJournal(missing); start != (Checkpoint{}) || err == nil {
		t.Fatal("missing local directory admitted")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private initialization created its missing directory")
	}
}

func TestDarwinLocalNativePreoperationKeyAndBuildDriftPoisons(t *testing.T) {
	for _, kind := range []string{"changed", "missing", "prefix", "short", "zero", "mode", "read-acl", "flag", "symlink", "hardlink", "build-commit", "build-state"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newDarwinLocalFixture(t, true)
			local := fixture.open(t, fixture.start)
			keyPath, journalPath := filepath.Join(fixture.path, actorKeyName), filepath.Join(fixture.path, journalName)
			original := darwinLocalCapture(t, keyPath)
			defer clear(original.data)
			payload := bytes.Clone(original.data)
			defer clear(payload)
			commit, sourceState := buildinfo.Commit, buildinfo.SourceState
			defer func() { buildinfo.Commit, buildinfo.SourceState = commit, sourceState }()
			switch kind {
			case "changed":
				payload[len(payload)-1] ^= 1
				darwinLocalRewriteKey(t, local, fixture.path, payload)
			case "missing":
				if os.Rename(keyPath, keyPath+".retained") != nil {
					t.Fatal("retain missing-name key fixture")
				}
			case "prefix":
				payload[0] ^= 1
				darwinLocalRewriteKey(t, local, fixture.path, payload)
			case "short":
				darwinLocalRewriteKey(t, local, fixture.path, payload[:len(payload)-1])
			case "zero":
				clear(payload[len(actorKeyPrefix):])
				darwinLocalRewriteKey(t, local, fixture.path, payload)
			case "mode":
				if os.Chmod(keyPath, 0640) != nil {
					t.Fatal("change owned key-mode fixture")
				}
			case "read-acl":
				darwinAuditFixtureACLCommand(t, keyPath, "+a", "everyone allow read,readattr,readextattr,readsecurity")
			case "flag":
				if unix.Chflags(keyPath, unix.UF_HIDDEN) != nil {
					t.Fatal("change owned key-flag fixture")
				}
			case "symlink":
				if os.Rename(keyPath, keyPath+".retained") != nil || os.Symlink(actorKeyName+".retained", keyPath) != nil {
					t.Fatal("change owned key-alias fixture")
				}
			case "hardlink":
				if os.Link(keyPath, keyPath+".alias") != nil {
					t.Fatal("change owned key-hardlink fixture")
				}
			case "build-commit":
				buildinfo.Commit = strings.Repeat("d", 40)
				if buildinfo.Commit == commit {
					buildinfo.Commit = strings.Repeat("e", 40)
				}
			case "build-state":
				buildinfo.SourceState = "modified"
				if buildinfo.SourceState == sourceState {
					buildinfo.SourceState = "clean"
				}
			}
			retainedKey := darwinLocalCapture(t, keyPath)
			defer clear(retainedKey.data)
			retainedJournal := darwinLocalCapture(t, journalPath)
			defer clear(retainedJournal.data)
			disk := &darwinJournalFaultDisk{delegate: local.journal.disk}
			local.journal.disk = disk
			head, err := local.Append(context.Background(), fixtureEvent(0))
			if err == nil || head != (Checkpoint{}) || disk.writes != 0 || disk.syncs != 0 || strings.Contains(err.Error(), fixture.path) {
				t.Fatal("changed key or current build admitted a write or disclosed private input")
			}
			if head, err := local.Append(context.Background(), fixtureEvent(1)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("poisoned private adapter retried recording")
			}
			if data, from, to, err := local.Snapshot(context.Background()); data != nil || from != (Checkpoint{}) || to != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("poisoned private adapter returned evidence")
			}
			if head, err := local.journal.Append(context.Background(), fixtureEvent(1)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) || disk.writes != 0 {
				t.Fatal("producer failure left the raw journal reusable")
			}
			darwinLocalPreserved(t, keyPath, retainedKey)
			darwinLocalPreserved(t, journalPath, retainedJournal)
			if local.Close() != nil {
				t.Fatal("poisoned private adapter close failed")
			}
		})
	}
}

func TestDarwinLocalNativeKeyCreationAndSemanticCommitFaults(t *testing.T) {
	t.Run("exact-native-key", func(t *testing.T) {
		fixture := newDarwinLocalFixture(t, false)
		dir := darwinAuditOpenFixtureScope(t, fixture.path)
		if createDarwinLocalActorKey(dir, [32]byte{}) == nil {
			t.Fatal("zero actor key created private storage")
		}
		if entries, err := os.ReadDir(fixture.path); err != nil || len(entries) != 0 {
			t.Fatal("zero-key refusal created a partial file")
		}
		key := [32]byte{1}
		defer clear(key[:])
		if createDarwinLocalActorKey(dir, key) != nil {
			t.Fatal("native framed key creation failed")
		}
		retained, err := readDarwinLocalActorKey(dir)
		defer clear(retained[:])
		if err != nil || retained != key {
			t.Fatal("native framed key did not read back exactly")
		}
		path := filepath.Join(fixture.path, actorKeyName)
		before := darwinLocalCapture(t, path)
		defer clear(before.data)
		if createDarwinLocalActorKey(dir, [32]byte{2}) == nil {
			t.Fatal("native framed key creation replaced an existing key")
		}
		darwinLocalPreserved(t, path, before)
	})
	for _, mode := range []string{"enospc", "partial", "short", "sync-request", "false-ack", "wrong-bytes"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newDarwinLocalFixture(t, false)
			dir := darwinAuditOpenFixtureScope(t, fixture.path)
			file, err := dir.createRegular(actorKeyName)
			if err != nil {
				t.Fatal("create exclusive actor-key fault candidate")
			}
			darwinAuditTrackFile(t, file)
			disk := &darwinJournalFaultDisk{delegate: &darwinJournalCommitter{file: file, parent: dir.dir}, mode: mode}
			key := [32]byte{1}
			defer clear(key[:])
			dir.mu.Lock()
			writeErr := writeDarwinLocalActorKeyLocked(dir, file, key, disk)
			dir.mu.Unlock()
			if !errors.Is(writeErr, ErrJournalUncertain) || disk.writes != 1 || file.Close() != nil {
				t.Fatal("actor-key semantic commit fault became successful initialization")
			}
			before := darwinLocalCapture(t, filepath.Join(fixture.path, actorKeyName))
			defer clear(before.data)
			// These are explicit committer faults. Nonfaulting Sync delegates
			// actual file+parent full sync; no native OS-error claim is made.
			if start, err := initializeDarwinLocalJournal(fixture.path); err == nil || start != (Checkpoint{}) {
				t.Fatal("uncertain key initialization was resumed or replaced implicitly")
			}
			darwinLocalPreserved(t, filepath.Join(fixture.path, actorKeyName), before)
			if _, err := os.Lstat(filepath.Join(fixture.path, journalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("uncertain actor key caused an implicit journal creation")
			}
		})
	}
}

type darwinLocalChangedKeyDisk struct {
	delegate        journalCommitter
	keyFile, parent *os.File
	payload         []byte
	mutations       int
}

func (disk *darwinLocalChangedKeyDisk) WriteAt(data []byte, offset int64) (int, error) {
	return disk.delegate.WriteAt(data, offset)
}
func (disk *darwinLocalChangedKeyDisk) Sync() error {
	if err := disk.delegate.Sync(); err != nil {
		return err
	}
	// The key descriptor was opened before Append. No directory facade is
	// reentered while the actual raw journal owns dir.mu during this callback.
	disk.mutations++
	return commitJournalBytes(&darwinJournalCommitter{file: disk.keyFile, parent: disk.parent}, disk.payload, 0)
}
func TestDarwinLocalNativePostCommitKeyDriftSuppressesHead(t *testing.T) {
	fixture := newDarwinLocalFixture(t, true)
	local := fixture.open(t, fixture.start)
	keyPath, journalPath := filepath.Join(fixture.path, actorKeyName), filepath.Join(fixture.path, journalName)
	key := darwinLocalCapture(t, keyPath)
	defer clear(key.data)
	journal := darwinLocalCapture(t, journalPath)
	defer clear(journal.data)
	keyFile, err := local.dir.openRegular(actorKeyName, true)
	if err != nil {
		t.Fatal("preopen exact owned key change descriptor")
	}
	darwinAuditTrackFile(t, keyFile)
	changed := bytes.Clone(key.data)
	defer clear(changed)
	changed[len(changed)-1] ^= 1
	if bytes.Equal(changed[len(actorKeyPrefix):], make([]byte, 32)) {
		changed[len(actorKeyPrefix)] = 1
	}
	disk := &darwinLocalChangedKeyDisk{delegate: local.journal.disk, keyFile: keyFile, parent: local.dir.dir, payload: changed}
	local.journal.disk = disk
	previousHead, previousSize := local.journal.head, local.journal.size
	line, expected, _ := Append(fixture.start, fixtureEvent(0))
	head, err := local.Append(context.Background(), fixtureEvent(0))
	if !errors.Is(err, ErrJournalUncertain) || head != (Checkpoint{}) || disk.mutations != 1 || local.journal.head != previousHead || local.journal.size != previousSize {
		t.Fatal("postcommit key drift released an unearned checkpoint or acknowledgment")
	}
	if head, err := local.Append(context.Background(), fixtureEvent(1)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) || disk.mutations != 1 {
		t.Fatal("postcommit producer failure retried recording")
	}
	if data, from, to, err := local.Snapshot(context.Background()); data != nil || from != (Checkpoint{}) || to != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("postcommit producer failure returned snapshot evidence")
	}
	if head, err := local.journal.Append(context.Background(), fixtureEvent(1)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("postcommit producer failure left the raw journal reusable")
	}
	retained := darwinLocalCapture(t, journalPath)
	defer clear(retained.data)
	if !bytes.Equal(retained.data, append(bytes.Clone(journal.data), line...)) {
		t.Fatal("postcommit producer failure lost or duplicated its uncertain tail")
	}
	if bytes.Contains(retained.data, key.data[len(actorKeyPrefix):]) || bytes.Contains(retained.data, changed[len(actorKeyPrefix):]) {
		t.Fatal("private actor key entered uncertain journal bytes")
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(retained.data[len(journal.data):]), fixture.start, expected); err != nil {
		t.Fatal("independently computed complete uncertain tail differs")
	}
	if local.Close() != nil {
		t.Fatal("postcommit private adapter close failed")
	}
	if reopened, err := openDarwinLocalJournal(context.Background(), fixture.path, fixture.start, expected); reopened != nil || err == nil {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatal("changed current key silently reenrolled an existing producer")
	}
	darwinLocalPreserved(t, journalPath, retained)
}

func TestDarwinLocalNativeSnapshotProducerFailureReturnsNoEvidence(t *testing.T) {
	fixture := newDarwinLocalFixture(t, true)
	local := fixture.open(t, fixture.start)
	key := darwinLocalCapture(t, filepath.Join(fixture.path, actorKeyName))
	defer clear(key.data)
	changed := bytes.Clone(key.data)
	defer clear(changed)
	changed[len(changed)-1] ^= 1
	darwinLocalRewriteKey(t, local, fixture.path, changed)
	before := darwinLocalCapture(t, filepath.Join(fixture.path, journalName))
	defer clear(before.data)
	disk := &darwinJournalFaultDisk{delegate: local.journal.disk}
	local.journal.disk = disk
	if data, from, to, err := local.Snapshot(context.Background()); data != nil || from != (Checkpoint{}) || to != (Checkpoint{}) || err == nil {
		t.Fatal("changed current producer released local snapshot evidence")
	}
	if head, err := local.Append(context.Background(), fixtureEvent(0)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) || disk.writes != 0 || disk.syncs != 0 {
		t.Fatal("snapshot producer failure did not poison its local session")
	}
	if head, err := local.journal.Append(context.Background(), fixtureEvent(0)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("snapshot producer failure did not poison its raw journal")
	}
	darwinLocalPreserved(t, filepath.Join(fixture.path, journalName), before)
}

func TestDarwinLocalNativeCancellationAndForeignProducerPreserveStorage(t *testing.T) {
	fixture := newDarwinLocalFixture(t, true)
	keyPath, journalPath := filepath.Join(fixture.path, actorKeyName), filepath.Join(fixture.path, journalName)
	key, journal := darwinLocalCapture(t, keyPath), darwinLocalCapture(t, journalPath)
	defer clear(key.data)
	defer clear(journal.data)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if opened, err := openDarwinLocalJournal(ctx, fixture.path, fixture.start, fixture.start); opened != nil || !errors.Is(err, context.Canceled) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("canceled private local open admitted work")
	}
	for _, field := range []string{"actor", "class", "build", "target"} {
		producer := fixture.start.Producer
		switch field {
		case "actor":
			producer.ActorSHA256 = strings.Repeat("e", 64)
			if producer.ActorSHA256 == fixture.start.Producer.ActorSHA256 {
				producer.ActorSHA256 = strings.Repeat("f", 64)
			}
		case "class":
			producer.ActorClass = "administrator"
		case "build":
			producer.SourceCommit = strings.Repeat("d", 40)
			if producer.SourceCommit == fixture.start.Producer.SourceCommit {
				producer.SourceCommit = strings.Repeat("e", 40)
			}
		case "target":
			producer.Target = "linux/amd64"
		}
		foreign, err := NewStream(producer)
		if err != nil {
			t.Fatal("prepare valid foreign producer fixture")
		}
		if opened, err := openDarwinLocalJournal(context.Background(), fixture.path, foreign, foreign); opened != nil || !errors.Is(err, ErrProcessIdentity) {
			if opened != nil {
				opened.Close()
			}
			t.Fatal("foreign current-process producer admitted")
		}
		darwinLocalPreserved(t, keyPath, key)
		darwinLocalPreserved(t, journalPath, journal)
	}
	local := fixture.open(t, fixture.start)
	disk := &darwinJournalFaultDisk{delegate: local.journal.disk}
	local.journal.disk = disk
	if head, err := local.Append(ctx, fixtureEvent(0)); head != (Checkpoint{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled private local append admitted work")
	}
	if data, from, to, err := local.Snapshot(ctx); data != nil || from != (Checkpoint{}) || to != (Checkpoint{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled private local snapshot returned evidence")
	}
	if disk.writes != 0 || disk.syncs != 0 {
		t.Fatal("canceled private local admission attempted a commit")
	}
	darwinLocalPreserved(t, keyPath, key)
	darwinLocalPreserved(t, journalPath, journal)
	active, cancelActive := context.WithCancel(context.Background())
	defer cancelActive()
	local.journal.disk = &darwinJournalCancelAfterWrite{delegate: disk.delegate, cancel: cancelActive}
	_, expected, _ := Append(fixture.start, fixtureEvent(0))
	if head, err := local.Append(active, fixtureEvent(0)); err != nil || head != expected || active.Err() == nil {
		t.Fatal("fully verified private local commit was lost after cancellation")
	}
}

func TestDarwinLocalNativeCloseAttemptsOwnedScopeAfterFirstFailure(t *testing.T) {
	for _, kind := range []string{"data-preclosed", "scope-preclosed"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newDarwinLocalFixture(t, true)
			local := fixture.open(t, fixture.start)
			owned := local.journal.file
			ancestors := append([]darwinAuditDirectoryBinding(nil), local.dir.ancestors...)
			if kind == "data-preclosed" {
				if owned.Close() != nil {
					t.Fatal("prepare deliberately preclosed private data file")
				}
			} else if local.dir.Close() != nil {
				t.Fatal("prepare deliberately preclosed owned scope")
			}
			closeErr := local.Close()
			if closeErr == nil || local.Close() != closeErr {
				t.Fatal("private local close did not retain its first failure")
			}
			if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("failed private local close retained data ownership")
			}
			for _, binding := range ancestors {
				if _, err := binding.file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("earlier close failure skipped an owned scope close")
				}
			}
			if head, err := local.Append(context.Background(), fixtureEvent(0)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("closed private local adapter accepted recording")
			}
			fixture.probe(t, fixture.start, darwinJournalChildAvailable)
		})
	}
	var missing *localDarwinJournal
	if missing.Close() != nil {
		t.Fatal("nil private local close acquired ownership")
	}
}

func TestDarwinPublicLocalWrappersRoundTrip(t *testing.T) {
	fixture := newDarwinLocalFixture(t, false)
	if !LocalRecordingSupported() {
		t.Fatal("native Darwin public recording capability is unavailable")
	}
	start, err := InitializeLocalJournal(fixture.path)
	if err != nil || start.Sequence != 0 || !validProducer(start.Producer) {
		t.Fatal("public Darwin journal initialization failed")
	}
	journal, err := OpenLocalJournal(context.Background(), fixture.path, start, start)
	if err != nil || journal == nil {
		t.Fatal("public Darwin journal opening failed")
	}
	t.Cleanup(func() {
		if journal.Close() != nil {
			t.Error("public Darwin journal cleanup failed")
		}
	})
	head, err := journal.Append(context.Background(), fixtureEvent(0))
	if err != nil {
		t.Fatal("public Darwin journal append failed")
	}
	data, from, to, err := journal.Snapshot(context.Background())
	if err != nil || from != start || to != head {
		t.Fatal("public Darwin snapshot endpoints differ")
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(data), start, head); err != nil {
		t.Fatal("public Darwin event segment failed verification")
	}
	var output bytes.Buffer
	if err := ExportLocalSegment(context.Background(), fixture.path, start, head, &output); !errors.Is(err, ErrJournalBusy) || output.Len() != 0 {
		t.Fatal("public Darwin export bypassed a held writer")
	}
	if journal.Close() != nil {
		t.Fatal("public Darwin journal close failed")
	}
	if err := ExportLocalSegment(context.Background(), fixture.path, start, head, &output); err != nil || !bytes.Equal(output.Bytes(), data) {
		t.Fatal("public Darwin historical export differs from retained snapshot")
	}
	if got, err := InitializeLocalJournal(fixture.path); err == nil || got != (Checkpoint{}) {
		t.Fatal("public Darwin initialization replaced existing storage")
	}
}
