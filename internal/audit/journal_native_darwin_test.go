//go:build darwin && (amd64 || arm64)

package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type darwinJournalFixture struct {
	fixture *darwinAuditNativeFixture
	dir     *darwinAuditDirectory
	path    string
	start   Checkpoint
}

func newDarwinJournalFixture(t *testing.T) *darwinJournalFixture {
	t.Helper()
	fixture := newDarwinAuditNativeFixture(t)
	path := fixture.directory(t, fixture.root, "stream")
	dir := darwinAuditOpenFixtureScope(t, path)
	producer := fixtureProducer()
	producer.Target = "darwin/" + runtime.GOARCH
	start, err := NewStream(producer)
	if err != nil {
		t.Fatal("create native journal genesis")
	}
	return &darwinJournalFixture{fixture, dir, path, start}
}
func (f *darwinJournalFixture) create(t *testing.T) *darwinJournal {
	t.Helper()
	journal, err := createDarwinJournal(f.dir, f.start)
	if err != nil || journal == nil {
		t.Fatal("native journal exclusive initialization failed")
	}
	f.track(t, journal)
	return journal
}
func (f *darwinJournalFixture) track(t *testing.T, journal *darwinJournal) {
	t.Helper()
	t.Cleanup(func() {
		if !journal.closed {
			if journal.Close() != nil {
				t.Error("owned native journal cleanup failed")
			}
		}
	})
}
func (f *darwinJournalFixture) bytes(t *testing.T) []byte {
	t.Helper()
	file, err := os.Open(filepath.Join(f.path, journalName))
	if err != nil {
		t.Fatal("open bounded fixture journal snapshot")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxJournalBytes+2))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > MaxJournalBytes+1 {
		t.Fatal("bounded fixture journal snapshot failed")
	}
	return data
}
func (f *darwinJournalFixture) refuse(t *testing.T, start, head Checkpoint) {
	t.Helper()
	before := f.bytes(t)
	node := darwinAuditFixtureNode(t, filepath.Join(f.path, journalName))
	journal, err := openDarwinJournal(context.Background(), f.dir, start, head)
	if journal != nil || err == nil {
		if journal != nil {
			journal.Close()
		}
		t.Fatal("unretained or corrupt journal endpoint admitted")
	}
	if !bytes.Equal(before, f.bytes(t)) || darwinAuditFixtureNode(t, filepath.Join(f.path, journalName)) != node {
		t.Fatal("endpoint refusal repaired or changed journal storage")
	}
}

func TestDarwinJournalExactGenesisAppendSnapshotReopen(t *testing.T) {
	f := newDarwinJournalFixture(t)
	journal := f.create(t)
	genesis, _ := EncodeCheckpoint(f.start)
	if darwinAuditAccessMode(t, journal.file) != unix.O_RDWR || !bytes.Equal(f.bytes(t), genesis) {
		t.Fatal("native initialization did not retain exact readable genesis bytes")
	}
	event := fixtureEvent(0)
	line, expected, err := Append(f.start, event)
	if err != nil {
		t.Fatal("prepare independently retained successor")
	}
	head, err := journal.Append(context.Background(), event)
	if err != nil || head != expected || !bytes.Equal(f.bytes(t), append(bytes.Clone(genesis), line...)) {
		t.Fatal("native append did not commit the exact independent successor")
	}
	segment, start, end, err := journal.Snapshot(context.Background())
	if err != nil || start != f.start || end != expected || !bytes.Equal(segment, line) {
		t.Fatal("native snapshot changed independently retained endpoints")
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(segment), start, end); err != nil {
		t.Fatal("native snapshot is not a valid retained chain")
	}
	retained := f.bytes(t)
	if journal.Close() != nil || f.dir.checkBinding() != nil {
		t.Fatal("journal close revoked its borrowed directory")
	}
	opened, err := openDarwinJournal(context.Background(), f.dir, f.start, expected)
	if err != nil {
		t.Fatal("exact retained journal could not reopen")
	}
	f.track(t, opened)
	again, from, to, err := opened.Snapshot(context.Background())
	if err != nil || from != start || to != end || !bytes.Equal(again, segment) || !bytes.Equal(retained, f.bytes(t)) {
		t.Fatal("native reopen changed verified evidence")
	}
	if opened.Close() != nil {
		t.Fatal("reopened journal close failed")
	}
	if created, err := createDarwinJournal(f.dir, f.start); created != nil || err == nil {
		if created != nil {
			created.Close()
		}
		t.Fatal("exclusive initialization replaced a retained stream")
	}
	if !bytes.Equal(retained, f.bytes(t)) {
		t.Fatal("exclusive initialization refusal changed bytes")
	}
}

func TestDarwinJournalConcurrentAppendProducesOneCompleteChain(t *testing.T) {
	f := newDarwinJournalFixture(t)
	journal := f.create(t)
	const count = 12
	var writers sync.WaitGroup
	for index := 0; index < count; index++ {
		writers.Add(1)
		go func(index int) {
			defer writers.Done()
			if _, err := journal.Append(context.Background(), fixtureEvent(index)); err != nil {
				t.Error("concurrent native journal append failed")
			}
		}(index)
	}
	writers.Wait()
	data, start, head, err := journal.Snapshot(context.Background())
	if err != nil || start != f.start || head.Sequence != count {
		t.Fatal("concurrent native journal snapshot failed")
	}
	if _, err := VerifySegment(context.Background(), bytes.NewReader(data), start, head); err != nil {
		t.Fatal("concurrent native journal has no complete linear chain")
	}
	seen := make(map[int64]int)
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		var entry record
		if json.Unmarshal(line, &entry) != nil {
			t.Fatal("concurrent journal record did not decode")
		}
		seen[entry.Event.OccurredAt.UnixNano()]++
		if entry.Event.Action != "profile.write" || entry.Event.Outcome != "intent" || entry.Event.OperationID != fixtureEvent(0).OperationID {
			t.Fatal("concurrent journal changed event metadata")
		}
	}
	for index := 0; index < count; index++ {
		if seen[fixtureEvent(index).OccurredAt.UnixNano()] != 1 {
			t.Fatal("concurrent journal lost or duplicated an event")
		}
	}
}

type darwinJournalFaultDisk struct {
	delegate        journalCommitter
	mode            string
	writes, syncs   int
	data            []byte
	offset          int64
	onWrite, onSync func()
}

func (disk *darwinJournalFaultDisk) WriteAt(data []byte, offset int64) (int, error) {
	disk.writes++
	disk.data, disk.offset = bytes.Clone(data), offset
	if disk.onWrite != nil {
		disk.onWrite()
	}
	switch disk.mode {
	case "enospc":
		return 0, syscall.ENOSPC
	case "partial", "short":
		n, err := disk.delegate.WriteAt(data[:len(data)/2], offset)
		if err != nil || disk.mode == "short" {
			return n, err
		}
		return n, io.ErrShortWrite
	case "false-ack":
		return len(data), nil
	case "wrong-bytes":
		wrong := bytes.Clone(data)
		wrong[0] ^= 1
		return disk.delegate.WriteAt(wrong, offset)
	}
	return disk.delegate.WriteAt(data, offset)
}
func (disk *darwinJournalFaultDisk) Sync() error {
	disk.syncs++
	if disk.mode == "sync-request" {
		// This is an injected committer request failure, not an observed OS
		// fsync/F_FULLFSYNC failure. Every nonfaulting path delegates both.
		return syscall.EIO
	}
	if err := disk.delegate.Sync(); err != nil {
		return err
	}
	if disk.onSync != nil {
		disk.onSync()
	}
	return nil
}

func TestDarwinJournalUncertainWritesPoisonAndPreserve(t *testing.T) {
	for _, mode := range []string{"enospc", "partial", "short", "sync-request", "false-ack", "wrong-bytes"} {
		t.Run(mode, func(t *testing.T) {
			f := newDarwinJournalFixture(t)
			journal := f.create(t)
			prior := f.bytes(t)
			priorHead, priorSize := journal.head, journal.size
			event := fixtureEvent(0)
			line, expected, _ := Append(f.start, event)
			disk := &darwinJournalFaultDisk{delegate: journal.disk, mode: mode}
			journal.disk = disk
			head, err := journal.Append(context.Background(), event)
			if !errors.Is(err, ErrJournalUncertain) || head != (Checkpoint{}) || disk.writes != 1 || journal.head != priorHead || journal.size != priorSize {
				t.Fatal("uncertain native commit returned an unearned head or changed acknowledgment")
			}
			if !bytes.Equal(disk.data, line) || disk.offset != int64(len(prior)) {
				t.Fatal("journal attempted a different record or offset")
			}
			syncs := disk.syncs
			if head, err := journal.Append(context.Background(), fixtureEvent(1)); !errors.Is(err, ErrJournalUnavailable) || head != (Checkpoint{}) || disk.writes != 1 || disk.syncs != syncs {
				t.Fatal("uncertain journal retried a write or sync")
			}
			data, start, end, err := journal.Snapshot(context.Background())
			if data != nil || start != (Checkpoint{}) || end != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("uncertain journal returned snapshot evidence")
			}
			retained := f.bytes(t)
			if !bytes.HasPrefix(retained, prior) || journal.Close() != nil {
				t.Fatal("uncertain journal damaged prior bytes or leaked its owned close")
			}
			switch mode {
			case "enospc", "false-ack":
				if !bytes.Equal(prior, retained) || (mode == "enospc" && disk.syncs != 0) || (mode == "false-ack" && disk.syncs != 1) {
					t.Fatal("zero-byte fault did not preserve the exact acknowledged stream")
				}
				opened, err := openDarwinJournal(context.Background(), f.dir, f.start, f.start)
				if err != nil || opened.Close() != nil {
					t.Fatal("unchanged stream could not reopen with its retained head")
				}
			case "partial", "short":
				if len(retained) <= len(prior) || disk.syncs != 0 {
					t.Fatal("partial-write fixture did not retain an uncertain tail")
				}
				f.refuse(t, f.start, f.start)
				f.refuse(t, f.start, expected)
			case "wrong-bytes":
				if len(retained) != len(prior)+len(line) || disk.syncs != 1 {
					t.Fatal("same-length corruption did not reach full-sync readback")
				}
				f.refuse(t, f.start, f.start)
				f.refuse(t, f.start, expected)
			case "sync-request":
				if disk.syncs != 1 || !bytes.Equal(retained, append(bytes.Clone(prior), line...)) {
					t.Fatal("sync-request failure did not preserve its complete unacknowledged tail")
				}
				f.refuse(t, f.start, f.start)
				opened, err := openDarwinJournal(context.Background(), f.dir, f.start, expected)
				if err != nil || opened.Close() != nil {
					t.Fatal("explicit independently computed reconciliation failed")
				}
			}
			if !bytes.Equal(retained, f.bytes(t)) {
				t.Fatal("refusal or explicit reconciliation repaired evidence")
			}
		})
	}
}

func TestDarwinJournalFullSyncOrderingAndCancellation(t *testing.T) {
	for _, phase := range []string{"after-write", "after-full-sync"} {
		t.Run(phase, func(t *testing.T) {
			f := newDarwinJournalFixture(t)
			journal := f.create(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			oldHead, oldSize := journal.head, journal.size
			event := fixtureEvent(0)
			line, expected, _ := Append(oldHead, event)
			disk := &darwinJournalFaultDisk{delegate: journal.disk}
			checkUnacknowledged := func() {
				if journal.head != oldHead || journal.size != oldSize {
					t.Error("in-flight native commit was acknowledged before full-sync verification")
				}
			}
			disk.onWrite = checkUnacknowledged
			disk.onSync = func() {
				checkUnacknowledged()
				cancel()
			}
			if phase == "after-write" {
				// Cancellation happens only after the actual WriteAt completes.
				disk.delegate = &darwinJournalCancelAfterWrite{delegate: journal.disk, cancel: cancel}
				disk.onSync = checkUnacknowledged
			}
			journal.disk = disk
			head, err := journal.Append(ctx, event)
			if err != nil || head != expected || ctx.Err() == nil || disk.writes != 1 || disk.syncs != 1 || disk.offset != oldSize || !bytes.Equal(disk.data, line) {
				t.Fatal("completed real full-sync commit was lost after cooperative cancellation")
			}
			if journal.head != expected || journal.size != oldSize+int64(len(line)) {
				t.Fatal("verified commit did not update the acknowledged state")
			}
		})
	}
	f := newDarwinJournalFixture(t)
	journal := f.create(t)
	before := f.bytes(t)
	disk := &darwinJournalFaultDisk{delegate: journal.disk}
	journal.disk = disk
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if head, err := journal.Append(ctx, fixtureEvent(0)); head != (Checkpoint{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled native append admitted work")
	}
	if data, start, head, err := journal.Snapshot(ctx); data != nil || start != (Checkpoint{}) || head != (Checkpoint{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled snapshot returned evidence")
	}
	invalid := fixtureEvent(0)
	invalid.Action = "unsupported"
	if head, err := journal.Append(context.Background(), invalid); err == nil || head != (Checkpoint{}) {
		t.Fatal("invalid event admitted a native write")
	}
	if disk.writes != 0 || disk.syncs != 0 || !bytes.Equal(before, f.bytes(t)) {
		t.Fatal("canceled or invalid admission mutated journal bytes")
	}
	if journal.Close() != nil {
		t.Fatal("canceled-admission journal close failed")
	}
	if opened, err := openDarwinJournal(ctx, f.dir, f.start, f.start); opened != nil || !errors.Is(err, context.Canceled) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("canceled native open admitted work")
	}
	if !bytes.Equal(before, f.bytes(t)) {
		t.Fatal("canceled native open changed bytes")
	}
}

type darwinJournalCancelAfterWrite struct {
	delegate journalCommitter
	cancel   context.CancelFunc
}

func (disk *darwinJournalCancelAfterWrite) WriteAt(data []byte, offset int64) (int, error) {
	n, err := disk.delegate.WriteAt(data, offset)
	disk.cancel()
	return n, err
}
func (disk *darwinJournalCancelAfterWrite) Sync() error { return disk.delegate.Sync() }

func TestDarwinJournalRetainedEndpointsCapacityAndPartialInitialization(t *testing.T) {
	f := newDarwinJournalFixture(t)
	journal := f.create(t)
	head, err := journal.Append(context.Background(), fixtureEvent(0))
	if err != nil || journal.Close() != nil {
		t.Fatal("prepare retained native endpoint fixture")
	}
	f.refuse(t, f.start, f.start)
	wrong := head
	wrong.SHA256 = strings.Repeat("f", 64)
	if wrong.SHA256 == head.SHA256 {
		wrong.SHA256 = strings.Repeat("e", 64)
	}
	f.refuse(t, f.start, wrong)
	foreign, err := NewStream(f.start.Producer)
	if err != nil {
		t.Fatal("prepare independent foreign genesis")
	}
	f.refuse(t, foreign, head)
	for _, data := range [][]byte{nil, []byte("{"), []byte("unknown\n")} {
		t.Run("partial-initialization", func(t *testing.T) {
			partial := newDarwinJournalFixture(t)
			darwinAuditFreshFile(t, filepath.Join(partial.path, journalName), data)
			before := partial.bytes(t)
			if created, err := createDarwinJournal(partial.dir, partial.start); created != nil || err == nil {
				if created != nil {
					created.Close()
				}
				t.Fatal("partial initialization was replaced")
			}
			partial.refuse(t, partial.start, partial.start)
			if !bytes.Equal(before, partial.bytes(t)) {
				t.Fatal("partial initialization changed")
			}
		})
	}
	capacity := newDarwinJournalFixture(t)
	original := capacity.create(t)
	if original.Close() != nil {
		t.Fatal("close capacity preparation owner")
	}
	genesis, _ := EncodeCheckpoint(capacity.start)
	full, last := bytes.Clone(genesis), capacity.start
	for index := 0; index < MaxSegmentRecords-1; index++ {
		line, next, err := Append(last, fixtureEvent(index))
		if err != nil {
			t.Fatal("prepare bounded canonical capacity stream")
		}
		full, last = append(full, line...), next
	}
	file, err := capacity.dir.openRegular(journalName, true)
	if err != nil {
		t.Fatal("open owned capacity preparation file")
	}
	if commitJournalBytes(&darwinJournalCommitter{file: file, parent: capacity.dir.dir}, full, 0) != nil || file.Close() != nil {
		t.Fatal("persist bounded capacity fixture through actual full sync")
	}
	opened, err := openDarwinJournal(context.Background(), capacity.dir, capacity.start, last)
	if err != nil {
		t.Fatal("independently retained capacity stream refused")
	}
	capacity.track(t, opened)
	if head, err := opened.Append(context.Background(), fixtureEvent(MaxSegmentRecords)); err != nil || head.Sequence != MaxSegmentRecords {
		t.Fatal("final reserved native record could not commit")
	}
	before := capacity.bytes(t)
	disk := &darwinJournalFaultDisk{delegate: opened.disk}
	opened.disk = disk
	if head, err := opened.Append(context.Background(), fixtureEvent(MaxSegmentRecords+1)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalFull) || disk.writes != 0 || disk.syncs != 0 || !bytes.Equal(before, capacity.bytes(t)) {
		t.Fatal("full native journal attempted another write")
	}
}

func TestDarwinJournalCloseOwnershipAndStickyFailure(t *testing.T) {
	f := newDarwinJournalFixture(t)
	journal := f.create(t)
	owned := journal.file
	if journal.Close() != nil || journal.Close() != nil || f.dir.checkBinding() != nil {
		t.Fatal("journal close is not idempotent or closed its borrowed scope")
	}
	if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("journal close retained its owned data descriptor")
	}
	if head, err := journal.Append(context.Background(), fixtureEvent(0)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("closed journal accepted append")
	}
	if data, start, head, err := journal.Snapshot(context.Background()); data != nil || start != (Checkpoint{}) || head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("closed journal returned snapshot evidence")
	}
	second := newDarwinJournalFixture(t)
	broken := second.create(t)
	if broken.file.Close() != nil {
		t.Fatal("prepare deliberately preclosed owned file")
	}
	closeErr := broken.Close()
	if !errors.Is(closeErr, ErrJournalStorage) || broken.Close() != closeErr || second.dir.checkBinding() != nil {
		t.Fatal("journal did not retain its first owned-close failure")
	}
	var missing *darwinJournal
	if missing.Close() != nil {
		t.Fatal("nil journal close acquired ownership")
	}
	if head, err := missing.Append(context.Background(), fixtureEvent(0)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("nil journal accepted append")
	}
	zero := &darwinJournal{}
	if zero.Close() != nil || zero.Close() != nil {
		t.Fatal("zero journal close is not safe and idempotent")
	}
}

const darwinJournalChildArgument = "-test.run=^TestDarwinJournalNativeChild$"
const darwinJournalChildMagic = "AWDJNL1\n"
const (
	darwinJournalChildAvailable byte = 1
	darwinJournalChildBusy      byte = 2
	darwinJournalChildHeld      byte = 3
	darwinJournalChildReleased  byte = 4
	darwinJournalChildWritten   byte = 5
)

type darwinJournalChildRequest struct {
	Nonce         [16]byte
	Parent, Child int
	Credentials   [4]int
	Arch          string
	Image         [32]byte
	Path          string
	Start, Head   Checkpoint
	Role          string
}
type darwinJournalOwnedChild struct {
	command        *exec.Cmd
	request, reply *os.File
	nonce          [16]byte
	done           chan struct{}
	waitErr        error
	waitStarted    bool
	fixture        *darwinAuditNativeFixture
}

func darwinJournalTestImage(t *testing.T) [32]byte {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("native journal child image unavailable")
	}
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal("open native journal child image")
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, io.LimitReader(file, (128<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || n == 0 || n > 128<<20 {
		t.Fatal("native journal child image is not bounded")
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}
func darwinJournalClosePipe(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Error("owned journal control pipe close failed")
	}
}
func startDarwinJournalChild(t *testing.T, f *darwinJournalFixture, head Checkpoint, role string) *darwinJournalOwnedChild {
	t.Helper()
	image := darwinJournalTestImage(t)
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		t.Fatal("create journal child request pipe")
	}
	replyRead, replyWrite, err := os.Pipe()
	if err != nil {
		requestRead.Close()
		requestWrite.Close()
		t.Fatal("create journal child reply pipe")
	}
	command := exec.Command(os.Args[0], darwinJournalChildArgument)
	// Only these two anonymous control pipes are inherited. The journal's
	// O_CLOEXEC data descriptor is never passed or duplicated to a contender.
	command.ExtraFiles = []*os.File{requestRead, replyWrite}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	child := &darwinJournalOwnedChild{command: command, request: requestWrite, reply: replyRead, done: make(chan struct{}), fixture: f.fixture}
	if _, err := rand.Read(child.nonce[:]); err != nil {
		for _, file := range []*os.File{requestRead, requestWrite, replyRead, replyWrite} {
			file.Close()
		}
		t.Fatal("create journal control nonce")
	}
	if command.Start() != nil {
		for _, file := range []*os.File{requestRead, requestWrite, replyRead, replyWrite} {
			file.Close()
		}
		t.Fatal("start owned native journal child")
	}
	t.Cleanup(func() {
		defer darwinJournalClosePipe(t, child.request)
		defer darwinJournalClosePipe(t, child.reply)
		if !child.waitStarted {
			// The child is still unreaped here, so its PID cannot be reused.
			// NEVER signal after Wait starts: Darwin has a reap-to-done gap.
			if err := child.command.Process.Kill(); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Error("owned journal child interruption failed")
			}
			child.startWait()
		}
		select {
		case <-child.done:
		case <-time.After(10 * time.Second):
			child.fixture.preserve = true
			t.Error("journal child exit unconfirmed; fixture preserved")
		}
	})
	darwinJournalClosePipe(t, requestRead)
	darwinJournalClosePipe(t, replyWrite)
	request := darwinJournalChildRequest{Nonce: child.nonce, Parent: os.Getpid(), Child: command.Process.Pid, Credentials: credentialSnapshot(), Arch: runtime.GOARCH, Image: image, Path: f.path, Start: f.start, Head: head, Role: role}
	data, err := json.Marshal(request)
	if err != nil || len(data) == 0 || len(data) > 8192 {
		t.Fatal("journal control request exceeded its fixed bound")
	}
	frame := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	if child.request.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
		t.Fatal("journal request deadline unavailable")
	}
	if n, err := child.request.Write(frame); err != nil || n != len(frame) {
		t.Fatal("journal bounded control request failed")
	}
	return child
}
func (child *darwinJournalOwnedChild) phase(t *testing.T, expected byte) {
	t.Helper()
	if child.reply.SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
		t.Fatal("journal reply deadline unavailable")
	}
	var frame [32]byte
	if _, err := io.ReadFull(child.reply, frame[:]); err != nil || string(frame[:8]) != darwinJournalChildMagic || !bytes.Equal(frame[8:24], child.nonce[:]) || frame[24] != expected || !bytes.Equal(frame[25:], make([]byte, 7)) {
		t.Fatal("native journal child fixed phase was not confirmed")
	}
}
func (child *darwinJournalOwnedChild) startWait() {
	if child.waitStarted {
		return
	}
	child.waitStarted = true
	go func() {
		child.waitErr = child.command.Wait() // The single and only Wait owner.
		close(child.done)
	}()
}
func (child *darwinJournalOwnedChild) reap(t *testing.T, killed bool) {
	t.Helper()
	// Normal callers reach a terminal phase only after actual data/scope
	// closes. They require natural exit0, including checked pipe cleanup.
	// Once Wait starts, neither this function nor cleanup may signal again.
	child.startWait()
	select {
	case <-child.done:
	case <-time.After(10 * time.Second):
		child.fixture.preserve = true
		t.Fatal("native journal child did not drain; fixture preserved")
	}
	if !killed {
		if child.waitErr != nil {
			t.Fatal("native journal child terminal cleanup failed")
		}
		return
	}
	var exit *exec.ExitError
	if !errors.As(child.waitErr, &exit) {
		t.Fatal("owned interruption did not terminate the held child")
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("owned journal interruption returned an unexpected exit")
	}
}
func (child *darwinJournalOwnedChild) release(t *testing.T) {
	t.Helper()
	if child.request.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
		t.Fatal("journal release deadline unavailable")
	}
	if n, err := child.request.Write([]byte{1}); err != nil || n != 1 {
		t.Fatal("journal child release failed")
	}
	child.phase(t, darwinJournalChildReleased)
	child.reap(t, false)
}
func (child *darwinJournalOwnedChild) kill(t *testing.T) {
	t.Helper()
	if child.waitStarted {
		t.Fatal("journal interruption attempted after Wait ownership release began")
	}
	if child.command.Process.Kill() != nil {
		t.Fatal("owned journal child interruption failed")
	}
	child.reap(t, true)
}
func darwinJournalChildReply(reply *os.File, nonce [16]byte, phase byte) error {
	var frame [32]byte
	copy(frame[:8], darwinJournalChildMagic)
	copy(frame[8:24], nonce[:])
	frame[24] = phase
	if reply.SetWriteDeadline(time.Now().Add(10*time.Second)) != nil {
		return io.ErrClosedPipe
	}
	if n, err := reply.Write(frame[:]); err != nil || n != len(frame) {
		return io.ErrClosedPipe
	}
	return nil
}
func darwinJournalChildRelease(request *os.File) error {
	if request.SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
		return io.ErrClosedPipe
	}
	var release [1]byte
	if _, err := io.ReadFull(request, release[:]); err != nil || release[0] != 1 {
		return io.ErrClosedPipe
	}
	return nil
}
func TestDarwinJournalNativeChild(t *testing.T) {
	if len(os.Args) != 2 || os.Args[1] != darwinJournalChildArgument {
		t.Skip("requires the private native journal child invocation")
	}
	home := darwinAuditNativeHome(t)
	// StartProcess exports ExtraFiles through File.Fd, which may make those
	// pipe descriptions blocking. Set the known control pipes nonblocking
	// before NewFile so it registers them with the runtime poller/deadlines.
	for _, control := range []struct{ fd, mode int }{{3, unix.O_RDONLY}, {4, unix.O_WRONLY}} {
		var stat unix.Stat_t
		flags, err := unix.FcntlInt(uintptr(control.fd), unix.F_GETFL, 0)
		if unix.Fstat(control.fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO ||
			err != nil || flags&unix.O_ACCMODE != control.mode || unix.SetNonblock(control.fd, true) != nil {
			t.Fatal("private journal control pipe preparation failed")
		}
	}
	request := os.NewFile(3, "native-journal-request")
	reply := os.NewFile(4, "native-journal-reply")
	if request == nil || reply == nil {
		t.Fatal("private journal control descriptors unavailable")
	}
	defer darwinJournalClosePipe(t, request)
	defer darwinJournalClosePipe(t, reply)
	for _, file := range []*os.File{request, reply} {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatal("private journal control descriptor is not a pipe")
		}
	}
	if darwinAuditAccessMode(t, request) != unix.O_RDONLY || darwinAuditAccessMode(t, reply) != unix.O_WRONLY || request.SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
		t.Fatal("private journal pipe direction or deadline unavailable")
	}
	var length [4]byte
	if _, err := io.ReadFull(request, length[:]); err != nil {
		t.Fatal("private journal request frame unavailable")
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > 8192 {
		t.Fatal("private journal request frame exceeds its bound")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(request, data); err != nil {
		t.Fatal("private journal request frame truncated")
	}
	var control darwinJournalChildRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&control) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("private journal request schema invalid")
	}
	relative, err := filepath.Rel(home, control.Path)
	parts := strings.Split(relative, string(os.PathSeparator))
	if err != nil || len(parts) != 2 || !strings.HasPrefix(parts[0], ".accessweaver-audit-native-") || parts[1] != "stream" ||
		control.Parent != os.Getppid() || control.Child != os.Getpid() || control.Credentials != credentialSnapshot() ||
		control.Arch != runtime.GOARCH || control.Image != darwinJournalTestImage(t) || control.Start.Producer.Target != "darwin/"+runtime.GOARCH {
		t.Fatal("private journal worker identity or fixture admission failed")
	}
	dir, err := openDarwinAuditDirectory(control.Path)
	if err != nil {
		t.Fatal("private journal child directory admission failed")
	}
	defer dir.Close()
	exclusive := control.Role == "probe-exclusive" || control.Role == "hold-exclusive" || control.Role == "partial-before-sync" || control.Role == "complete-before-sync"
	switch control.Role {
	case "probe-exclusive", "probe-shared":
		file, err := dir.openRegular(journalName, exclusive)
		if err != nil {
			t.Fatal("private journal lock probe open failed")
		}
		lockErr := lockDarwinAuditJournal(file, exclusive)
		if file.Close() != nil || dir.Close() != nil {
			t.Fatal("private journal lock probe close failed")
		}
		phase := darwinJournalChildAvailable
		if errors.Is(lockErr, ErrJournalBusy) {
			phase = darwinJournalChildBusy
		} else if lockErr != nil {
			t.Fatal("private journal lock probe failed")
		}
		if darwinJournalChildReply(reply, control.Nonce, phase) != nil {
			t.Fatal("private journal lock probe acknowledgment failed")
		}
	case "hold-exclusive", "partial-before-sync", "complete-before-sync":
		journal, err := openDarwinJournal(context.Background(), dir, control.Start, control.Head)
		if err != nil {
			t.Fatal("private journal writer endpoint admission failed")
		}
		defer journal.Close()
		if control.Role != "hold-exclusive" {
			journal.disk = &darwinJournalChildPauseDisk{delegate: journal.disk, request: request, reply: reply, nonce: control.Nonce, partial: control.Role == "partial-before-sync"}
			head, err := journal.Append(context.Background(), fixtureEvent(0))
			if !errors.Is(err, ErrJournalUncertain) || head != (Checkpoint{}) {
				t.Fatal("interrupted child unexpectedly acknowledged a successor")
			}
			return
		}
		if darwinJournalChildReply(reply, control.Nonce, darwinJournalChildHeld) != nil || darwinJournalChildRelease(request) != nil || journal.Close() != nil || dir.Close() != nil ||
			darwinJournalChildReply(reply, control.Nonce, darwinJournalChildReleased) != nil {
			t.Fatal("private journal held writer lifecycle failed")
		}
	case "hold-shared":
		file, err := dir.openRegular(journalName, false)
		if err != nil {
			t.Fatal("private journal shared-reader open failed")
		}
		defer file.Close()
		if lockDarwinAuditJournal(file, false) != nil {
			t.Fatal("private journal shared-reader lock failed")
		}
		dir.mu.Lock()
		state, stateErr := dir.fileStateLocked(file, journalName)
		var verifyErr error
		if stateErr == nil {
			_, verifyErr = readDarwinAuditJournalLocked(context.Background(), dir, file, control.Start, control.Head, state.size)
		}
		dir.mu.Unlock()
		if stateErr != nil || verifyErr != nil {
			t.Fatal("private journal shared-reader endpoint verification failed")
		}
		if darwinJournalChildReply(reply, control.Nonce, darwinJournalChildHeld) != nil || darwinJournalChildRelease(request) != nil || file.Close() != nil || dir.Close() != nil ||
			darwinJournalChildReply(reply, control.Nonce, darwinJournalChildReleased) != nil {
			t.Fatal("private journal held reader lifecycle failed")
		}
	default:
		t.Fatal("private journal worker role refused")
	}
}

type darwinJournalChildPauseDisk struct {
	delegate       journalCommitter
	request, reply *os.File
	nonce          [16]byte
	partial        bool
}

func (disk *darwinJournalChildPauseDisk) WriteAt(data []byte, offset int64) (int, error) {
	if disk.partial {
		data = data[:len(data)/2]
	}
	n, err := disk.delegate.WriteAt(data, offset)
	if err != nil || n != len(data) {
		return n, io.ErrShortWrite
	}
	if darwinJournalChildReply(disk.reply, disk.nonce, darwinJournalChildWritten) != nil || darwinJournalChildRelease(disk.request) != nil {
		return n, io.ErrClosedPipe
	}
	// Even an unexpected cooperative release cannot emit a checkpoint or
	// proceed into Sync in this test-private before-sync interruption role.
	return n, io.ErrClosedPipe
}
func (disk *darwinJournalChildPauseDisk) Sync() error { return disk.delegate.Sync() }

func TestDarwinJournalIndependentNativeFlocks(t *testing.T) {
	f := newDarwinJournalFixture(t)
	journal := f.create(t)
	other, err := f.dir.openRegular(journalName, true)
	if err != nil {
		t.Fatal("open independent native data-handle contender")
	}
	for _, exclusive := range []bool{true, false} {
		if !errors.Is(lockDarwinAuditJournal(other, exclusive), ErrJournalBusy) {
			t.Fatal("independent data handle bypassed the native writer lock")
		}
	}
	if other.Close() != nil {
		t.Fatal("close independent lock contender")
	}
	for _, role := range []string{"probe-exclusive", "probe-shared"} {
		child := startDarwinJournalChild(t, f, f.start, role)
		child.phase(t, darwinJournalChildBusy)
		child.reap(t, false)
	}
	if journal.Close() != nil {
		t.Fatal("close parent native writer")
	}
	child := startDarwinJournalChild(t, f, f.start, "hold-exclusive")
	child.phase(t, darwinJournalChildHeld)
	for _, exclusive := range []bool{true, false} {
		file, err := f.dir.openRegular(journalName, exclusive)
		if err != nil {
			t.Fatal("open parent contender against child writer")
		}
		lockErr := lockDarwinAuditJournal(file, exclusive)
		if file.Close() != nil || !errors.Is(lockErr, ErrJournalBusy) {
			t.Fatal("parent bypassed independently opened child writer lock")
		}
	}
	child.release(t)
	opened, err := openDarwinJournal(context.Background(), f.dir, f.start, f.start)
	if err != nil || opened.Close() != nil {
		t.Fatal("child writer final close did not release native lock")
	}
	reader, err := f.dir.openRegular(journalName, false)
	if err != nil || lockDarwinAuditJournal(reader, false) != nil {
		t.Fatal("parent native shared-reader admission failed")
	}
	darwinAuditTrackFile(t, reader)
	shared := startDarwinJournalChild(t, f, f.start, "hold-shared")
	shared.phase(t, darwinJournalChildHeld)
	for index := 0; index < 2; index++ {
		contender, err := f.dir.openRegular(journalName, true)
		if err != nil {
			t.Fatal("open writer against native shared owners")
		}
		lockErr := lockDarwinAuditJournal(contender, true)
		if contender.Close() != nil || !errors.Is(lockErr, ErrJournalBusy) {
			t.Fatal("writer bypassed a remaining native shared owner")
		}
		if index == 0 && reader.Close() != nil {
			t.Fatal("close first native shared reader")
		}
	}
	shared.release(t)
	reopened, err := openDarwinJournal(context.Background(), f.dir, f.start, f.start)
	if err != nil || reopened.Close() != nil {
		t.Fatal("last shared-owner close did not release native lock")
	}
}

func TestDarwinJournalKillBeforeSyncPreservesUnknownTail(t *testing.T) {
	for _, role := range []string{"partial-before-sync", "complete-before-sync"} {
		t.Run(role, func(t *testing.T) {
			f := newDarwinJournalFixture(t)
			journal := f.create(t)
			prior := f.bytes(t)
			line, expected, _ := Append(f.start, fixtureEvent(0))
			if journal.Close() != nil {
				t.Fatal("close parent before independent interrupted writer")
			}
			child := startDarwinJournalChild(t, f, f.start, role)
			child.phase(t, darwinJournalChildWritten)
			probe := startDarwinJournalChild(t, f, f.start, "probe-exclusive")
			probe.phase(t, darwinJournalChildBusy)
			probe.reap(t, false)
			child.kill(t)
			retained := f.bytes(t)
			if len(retained) <= len(prior) || !bytes.HasPrefix(retained, prior) {
				t.Fatal("process interruption lost its original prefix or uncertain tail")
			}
			f.refuse(t, f.start, f.start)
			if role == "partial-before-sync" {
				if len(retained) >= len(prior)+len(line) {
					t.Fatal("partial interruption did not retain a partial record")
				}
				f.refuse(t, f.start, expected)
			} else {
				if !bytes.Equal(retained, append(bytes.Clone(prior), line...)) {
					t.Fatal("complete interruption changed the independent record")
				}
				opened, err := openDarwinJournal(context.Background(), f.dir, f.start, expected)
				if err != nil || opened.Close() != nil {
					t.Fatal("explicit complete-tail reconciliation failed after child exit")
				}
			}
			available := startDarwinJournalChild(t, f, f.start, "probe-exclusive")
			available.phase(t, darwinJournalChildAvailable)
			available.reap(t, false)
			if !bytes.Equal(retained, f.bytes(t)) {
				t.Fatal("interruption refusal or reconciliation repaired retained bytes")
			}
		})
	}
}

type darwinJournalPauseDisk struct {
	delegate journalCommitter
	entered  chan struct{}
	release  chan struct{}
}

func (disk *darwinJournalPauseDisk) WriteAt(data []byte, offset int64) (int, error) {
	n, err := disk.delegate.WriteAt(data, offset)
	if err != nil || n != len(data) {
		return n, err
	}
	close(disk.entered)
	// Only the test-owned barrier is bounded. No native call is abandoned.
	select {
	case <-disk.release:
		return n, nil
	case <-time.After(10 * time.Second):
		return n, io.ErrClosedPipe
	}
}
func (disk *darwinJournalPauseDisk) Sync() error { return disk.delegate.Sync() }

func TestDarwinJournalCloseWaitsForActiveCommit(t *testing.T) {
	for _, owner := range []string{"journal", "scope"} {
		t.Run(owner, func(t *testing.T) {
			f := newDarwinJournalFixture(t)
			journal := f.create(t)
			line, expected, _ := Append(f.start, fixtureEvent(0))
			genesis, _ := EncodeCheckpoint(f.start)
			disk := &darwinJournalPauseDisk{delegate: journal.disk, entered: make(chan struct{}), release: make(chan struct{})}
			journal.disk = disk
			appendDone, closeDone, closeStarted := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var head Checkpoint
			var appendErr, closeErr error
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(disk.release) }) }
			closerLaunched := false
			t.Cleanup(func() {
				release()
				// The native full-sync owner remains retained until completion.
				<-appendDone
				if closerLaunched {
					<-closeDone
				}
			})
			go func() {
				head, appendErr = journal.Append(context.Background(), fixtureEvent(0))
				close(appendDone)
			}()
			select {
			case <-disk.entered:
			case <-appendDone:
				t.Fatal("controlled append did not reach its actual write")
			case <-time.After(10 * time.Second):
				t.Fatal("controlled source barrier was not reached")
			}
			closerLaunched = true
			go func() {
				close(closeStarted)
				if owner == "journal" {
					closeErr = journal.Close()
				} else {
					closeErr = f.dir.Close()
				}
				close(closeDone)
			}()
			<-closeStarted
			// The contender never waits on the parent's Go mutex or inherits
			// its data descriptor; the actual separate-process flock refuses.
			probe := startDarwinJournalChild(t, f, f.start, "probe-exclusive")
			probe.phase(t, darwinJournalChildBusy)
			probe.reap(t, false)
			select {
			case <-closeDone:
				t.Fatal("close released ownership before the active full-sync commit")
			default:
			}
			release()
			<-appendDone
			<-closeDone
			if appendErr != nil || head != expected || closeErr != nil || !bytes.Equal(f.bytes(t), append(bytes.Clone(genesis), line...)) {
				t.Fatal("serialized close lost a completed commit or changed bytes")
			}
			if owner == "journal" {
				if f.dir.checkBinding() != nil || journal.Close() != nil {
					t.Fatal("journal close revoked borrowed scope or changed its result")
				}
			} else {
				owned := journal.file
				err := journal.Close()
				if err == nil || journal.Close() != err {
					t.Fatal("journal close concealed the deliberately closed borrowed scope")
				}
				if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("bad borrowed scope prevented owned data close")
				}
			}
		})
	}
}
func TestDarwinJournalPrewriteCorruptionAndClosedScopeDoNotWrite(t *testing.T) {
	for _, mode := range []string{"partial-tail", "changed-genesis", "closed-scope"} {
		t.Run(mode, func(t *testing.T) {
			f := newDarwinJournalFixture(t)
			journal := f.create(t)
			before := f.bytes(t)
			switch mode {
			case "partial-tail":
				if _, err := journal.file.WriteAt([]byte("{"), int64(len(before))); err != nil {
					t.Fatal("prepare unknown prewrite tail")
				}
			case "changed-genesis":
				if _, err := journal.file.WriteAt([]byte("["), 0); err != nil {
					t.Fatal("prepare changed prewrite genesis")
				}
			case "closed-scope":
				if f.dir.Close() != nil {
					t.Fatal("close borrowed scope before native admission")
				}
			}
			retained := f.bytes(t)
			disk := &darwinJournalFaultDisk{delegate: journal.disk}
			journal.disk = disk
			head, err := journal.Append(context.Background(), fixtureEvent(0))
			if err == nil || head != (Checkpoint{}) || disk.writes != 0 || disk.syncs != 0 || !bytes.Equal(retained, f.bytes(t)) {
				t.Fatal("prewrite corruption or closed scope admitted mutation")
			}
			if head, err := journal.Append(context.Background(), fixtureEvent(1)); head != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) || disk.writes != 0 {
				t.Fatal("failed prewrite journal remained available")
			}
			if data, from, to, err := journal.Snapshot(context.Background()); data != nil || from != (Checkpoint{}) || to != (Checkpoint{}) || !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("failed prewrite journal returned evidence")
			}
			owned := journal.file
			closeErr := journal.Close()
			if (mode == "closed-scope") != (closeErr != nil) || journal.Close() != closeErr {
				t.Fatal("prewrite close did not preserve its ownership result")
			}
			if _, err := owned.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("prewrite failure leaked the owned data descriptor")
			}
			if mode != "closed-scope" {
				f.refuse(t, f.start, f.start)
			}
		})
	}
}
func TestDarwinJournalFullSyncRefusesInvalidDescriptors(t *testing.T) {
	f := newDarwinJournalFixture(t)
	file, err := f.dir.createRegular(journalName)
	if err != nil {
		t.Fatal("create invalid-descriptor full-sync control")
	}
	if file.Close() != nil || !errors.Is(darwinFullSync(file), ErrJournalUncertain) || !errors.Is(darwinFullSync(nil), ErrJournalUncertain) {
		t.Fatal("invalid full-sync descriptor became a successful durability request")
	}
	// This is invalid descriptor admission, not a simulated filesystem or
	// hardware error in a particular native fsync/F_FULLFSYNC stage.
}
