package profile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
)

// Reported faults below are semantic cofactors after the real owned operation.
// They do not claim a native kernel/ACL fault or select a production backend.
type atomicWriteFixture struct {
	root        string
	destination string
	stages      []*atomicWriteTestStage
	preserve    atomic.Bool
}
type atomicWriteTestStage struct {
	file                                          *os.File
	fixture                                       *atomicWriteFixture
	mode                                          string
	chmodFault, writeFault, syncFault, closeFault error
	panicAfterWrite                               any
	beforeClose                                   func()
	chmodCalls, writeCalls, syncCalls, closeCalls atomic.Int32
	closed                                        atomic.Bool
}

func newAtomicWriteFixture(t *testing.T) *atomicWriteFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-atomic-write-")
	if err != nil {
		t.Fatal("owned atomic fixture unavailable")
	}
	state, err := fileidentity.FromPath(root, false)
	if err != nil {
		t.Fatal("owned atomic fixture identity unavailable")
	}
	f := &atomicWriteFixture{root: root, destination: filepath.Join(root, "destination.txt")}
	t.Cleanup(func() {
		if f.preserve.Load() {
			t.Error("unconfirmed atomic fixture retained")
			return
		}
		for _, stage := range f.stages {
			if stage.closeCalls.Load() == 0 {
				if err := stage.Close(); err != nil && !stage.closed.Load() {
					f.preserve.Store(true)
				}
			}
			if !stage.closed.Load() {
				f.preserve.Store(true)
			}
		}
		if f.preserve.Load() {
			t.Error("unconfirmed atomic stage retained")
			return
		}
		current, err := fileidentity.FromPath(root, false)
		if err != nil || current.Kind != state.Kind || current.ID != state.ID {
			t.Error("changed atomic fixture retained")
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("owned atomic fixture cleanup failed")
		}
	})
	if err := os.WriteFile(f.destination, []byte("old destination"), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *atomicWriteFixture) ops(configure func(*atomicWriteTestStage)) atomicWriteOperations {
	return atomicWriteOperations{mkdirAll: os.MkdirAll, createTemp: func(dir, pattern string) (atomicWriteStage, error) {
		file, err := os.CreateTemp(dir, pattern)
		if file == nil {
			return nil, err
		}
		stage := &atomicWriteTestStage{file: file, fixture: f}
		f.stages = append(f.stages, stage)
		if configure != nil {
			configure(stage)
		}
		return stage, err
	}, replace: replaceFile}
}
func (s *atomicWriteTestStage) Name() string { return s.file.Name() }
func (s *atomicWriteTestStage) Chmod(mode os.FileMode) error {
	s.chmodCalls.Add(1)
	if err := s.file.Chmod(mode); err != nil {
		return err
	}
	return s.chmodFault
}
func (s *atomicWriteTestStage) Write(data []byte) (int, error) {
	s.writeCalls.Add(1)
	payload := data
	if s.mode == "short" || s.mode == "short-error" {
		payload = data[:len(data)/2]
	} else if s.mode == "zero" {
		payload = data[:0]
	}
	n, err := s.file.Write(payload)
	if err != nil {
		return n, err
	}
	if s.panicAfterWrite != nil {
		panic(s.panicAfterWrite)
	}
	if s.mode == "negative" {
		return -1, s.writeFault
	}
	if s.mode == "oversized" {
		return len(data) + 1, s.writeFault
	}
	return n, s.writeFault
}
func (s *atomicWriteTestStage) Sync() error {
	s.syncCalls.Add(1)
	if err := s.file.Sync(); err != nil {
		return err
	}
	return s.syncFault
}
func (s *atomicWriteTestStage) Close() error {
	if s.closeCalls.Add(1) != 1 {
		s.fixture.preserve.Store(true)
		return errors.New("fixture Close repeated")
	}
	if s.beforeClose != nil {
		s.beforeClose()
	}
	if err := s.file.Close(); err != nil {
		s.fixture.preserve.Store(true)
		return err
	}
	s.closed.Store(true)
	return s.closeFault
}
func assertAtomicWriteUncertain(t *testing.T, err error, causes ...error) {
	t.Helper()
	if !errors.Is(err, ErrAtomicWriteUncertain) || err.Error() != ErrAtomicWriteUncertain.Error() {
		t.Fatal("atomic failure lost its fixed private framing")
	}
	for _, cause := range causes {
		if !errors.Is(err, cause) {
			t.Fatal("atomic failure lost an owned operation cause")
		}
	}
}
func assertAtomicBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, want) {
		t.Fatal("owned atomic file bytes differ")
	}
}
func assertAtomicClosed(t *testing.T, f *atomicWriteFixture, s *atomicWriteTestStage) {
	t.Helper()
	if s.closeCalls.Load() != 1 || !s.closed.Load() {
		f.preserve.Store(true)
		t.Fatal("owned stage was not physically closed once")
	}
	// Nonempty public I/O demonstrates actual closure independently of the
	// semantic error returned after the real Close above.
	if n, err := s.file.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
		f.preserve.Store(true)
		t.Fatal("actual closed-stage probe failed")
	}
}

func TestAtomicWriteOwnedBodyAndCloseCofailures(t *testing.T) {
	for _, phase := range []string{"chmod", "write", "sync", "close"} {
		t.Run(phase, func(t *testing.T) {
			f := newAtomicWriteFixture(t)
			body := errors.New("PRIVATE_ATOMIC_BODY")
			closed := errors.New("PRIVATE_ATOMIC_CLOSE")
			ops := f.ops(func(s *atomicWriteTestStage) {
				s.closeFault = &os.PathError{Op: "close", Path: "PRIVATE_STAGE_CLOSE", Err: closed}
				switch phase {
				case "chmod":
					s.chmodFault = body
				case "write":
					s.writeFault = body
				case "sync":
					s.syncFault = body
				}
			})
			published := 0
			ops.replace = func(string, string) error { published++; return nil }
			err := atomicWrite(f.destination, []byte("new staged bytes"), ops)
			assertAtomicWriteUncertain(t, err, closed)
			if phase != "close" && !errors.Is(err, body) {
				t.Fatal("body/Close cofailure lost")
			}
			s := f.stages[0]
			assertAtomicClosed(t, f, s)
			if published != 0 {
				t.Fatal("unconfirmed stage was published")
			}
			if s.chmodCalls.Load() != 1 || s.writeCalls.Load() > 1 || s.syncCalls.Load() > 1 {
				t.Fatal("stage operation repeated")
			}
			if phase == "chmod" && (s.writeCalls.Load() != 0 || s.syncCalls.Load() != 0) {
				t.Fatal("write/sync followed failed Chmod")
			}
			if phase == "write" && s.syncCalls.Load() != 0 {
				t.Fatal("sync followed failed Write")
			}
			assertAtomicBytes(t, f.destination, []byte("old destination"))
			if _, err := os.Lstat(s.Name()); err != nil {
				t.Fatal("failed closed stage was removed")
			}
		})
	}
}

func TestAtomicWriteExactCountsRejectWithoutSyncOrPublish(t *testing.T) {
	for _, mode := range []string{"short", "short-error", "zero", "negative", "oversized", "full-error", "empty-error"} {
		t.Run(mode, func(t *testing.T) {
			f := newAtomicWriteFixture(t)
			fault := errors.New("PRIVATE_WRITE_CAUSE")
			data := []byte("counted payload")
			if mode == "empty-error" {
				data = nil
			}
			ops := f.ops(func(s *atomicWriteTestStage) {
				s.mode = mode
				if mode != "short" && mode != "zero" {
					s.writeFault = fault
				}
			})
			published := 0
			ops.replace = func(string, string) error { published++; return nil }
			err := atomicWrite(f.destination, data, ops)
			assertAtomicWriteUncertain(t, err)
			if mode == "full-error" || mode == "empty-error" {
				if errors.Is(err, io.ErrShortWrite) {
					t.Fatal("full count was invented as short")
				}
			} else if !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short or invalid count accepted")
			}
			if mode != "short" && mode != "zero" && !errors.Is(err, fault) {
				t.Fatal("count failure lost supplied cause")
			}
			s := f.stages[0]
			assertAtomicClosed(t, f, s)
			if s.writeCalls.Load() != 1 || s.syncCalls.Load() != 0 || published != 0 {
				t.Fatal("failed count retried/synced/published")
			}
			want := data
			if mode == "short" || mode == "short-error" {
				want = data[:len(data)/2]
			} else if mode == "zero" {
				want = data[:0]
			}
			assertAtomicBytes(t, s.Name(), want)
			assertAtomicBytes(t, f.destination, []byte("old destination"))
		})
	}
}

func TestAtomicWriteEmptyAndCompletePublishOnlyAfterClose(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("complete data")} {
		t.Run(map[bool]string{true: "empty", false: "nonempty"}[len(data) == 0], func(t *testing.T) {
			f := newAtomicWriteFixture(t)
			ops := f.ops(nil)
			published := 0
			ops.replace = func(src, dst string) error {
				published++
				s := f.stages[0]
				assertAtomicClosed(t, f, s)
				if s.chmodCalls.Load() != 1 || s.writeCalls.Load() != 1 || s.syncCalls.Load() != 1 {
					t.Fatal("publication preceded complete pipeline")
				}
				return replaceFile(src, dst)
			}
			if err := atomicWrite(f.destination, data, ops); err != nil {
				t.Fatal(err)
			}
			if published != 1 {
				t.Fatal("publication skipped or repeated")
			}
			assertAtomicClosed(t, f, f.stages[0])
			assertAtomicBytes(t, f.destination, data)
		})
	}
}

func TestAtomicWritePrecreateAndPartialOwnerFailures(t *testing.T) {
	t.Run("mkdir", func(t *testing.T) {
		f := newAtomicWriteFixture(t)
		blocked := filepath.Join(f.root, "owned-parent-file")
		if err := os.WriteFile(blocked, []byte("block"), 0600); err != nil {
			t.Fatal(err)
		}
		err := AtomicWrite(filepath.Join(blocked, "target"), []byte("new"))
		assertAtomicWriteUncertain(t, err)
		var native *os.PathError
		if !errors.As(err, &native) {
			t.Fatal("native precreate cause lost")
		}
		assertAtomicBytes(t, blocked, []byte("block"))
		assertAtomicBytes(t, f.destination, []byte("old destination"))
	})
	t.Run("create", func(t *testing.T) {
		f := newAtomicWriteFixture(t)
		target := filepath.Join(f.root, "fresh-parent", "target")
		ops := f.ops(nil)
		ops.createTemp = func(dir, pattern string) (atomicWriteStage, error) {
			if err := os.Remove(dir); err != nil {
				return nil, err
			}
			file, err := os.CreateTemp(dir, pattern)
			if file != nil {
				f.preserve.Store(true)
				return &atomicWriteTestStage{file: file, fixture: f}, err
			}
			return nil, err
		}
		err := atomicWrite(target, []byte("new"), ops)
		assertAtomicWriteUncertain(t, err, os.ErrNotExist)
		if len(f.stages) != 0 {
			t.Fatal("failed Create invented an owned stage")
		}
	})
	t.Run("partial-owner", func(t *testing.T) {
		f := newAtomicWriteFixture(t)
		body, closed := errors.New("PRIVATE_CREATE"), errors.New("PRIVATE_CREATE_CLOSE")
		ops := f.ops(func(s *atomicWriteTestStage) { s.closeFault = closed })
		create := ops.createTemp
		ops.createTemp = func(dir, pattern string) (atomicWriteStage, error) {
			s, err := create(dir, pattern)
			if err != nil {
				return s, err
			}
			return s, body
		}
		published := 0
		ops.replace = func(string, string) error { published++; return nil }
		err := atomicWrite(f.destination, []byte("not written"), ops)
		assertAtomicWriteUncertain(t, err, body, closed)
		s := f.stages[0]
		assertAtomicClosed(t, f, s)
		if s.chmodCalls.Load() != 0 || s.writeCalls.Load() != 0 || s.syncCalls.Load() != 0 || published != 0 {
			t.Fatal("partial owner error continued pipeline")
		}
		assertAtomicBytes(t, s.Name(), nil)
		assertAtomicBytes(t, f.destination, []byte("old destination"))
	})
}

func TestAtomicWriteRealReplaceFailureRetainsOldDestinationAndClosedStage(t *testing.T) {
	f := newAtomicWriteFixture(t)
	target := filepath.Join(f.root, "nonempty-directory")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(target, "kept.txt")
	if err := os.WriteFile(kept, []byte("kept"), 0600); err != nil {
		t.Fatal(err)
	}
	ops := f.ops(nil)
	published := 0
	ops.replace = func(src, dst string) error {
		published++
		assertAtomicClosed(t, f, f.stages[0])
		return replaceFile(src, dst)
	}
	err := atomicWrite(target, []byte("new bytes"), ops)
	assertAtomicWriteUncertain(t, err)
	if published != 1 {
		t.Fatal("replace failed without actual single native attempt")
	}
	assertAtomicClosed(t, f, f.stages[0])
	assertAtomicBytes(t, f.stages[0].Name(), []byte("new bytes"))
	assertAtomicBytes(t, kept, []byte("kept"))
}

func TestAtomicWriteAfterRealPublicationErrorDoesNotRollback(t *testing.T) {
	f := newAtomicWriteFixture(t)
	cause := errors.New("PRIVATE_AFTER_PUBLISH")
	ops := f.ops(nil)
	published := 0
	ops.replace = func(src, dst string) error {
		published++
		assertAtomicClosed(t, f, f.stages[0])
		if err := replaceFile(src, dst); err != nil {
			return err
		}
		return cause
	}
	err := atomicWrite(f.destination, []byte("published despite error"), ops)
	assertAtomicWriteUncertain(t, err, cause)
	if published != 1 {
		t.Fatal("publication retried")
	}
	assertAtomicClosed(t, f, f.stages[0])
	assertAtomicBytes(t, f.destination, []byte("published despite error"))
}

func TestAtomicWriteSuccessNeverDeletesReoccupiedOldStageName(t *testing.T) {
	f := newAtomicWriteFixture(t)
	ops := f.ops(nil)
	ops.replace = func(src, dst string) error {
		assertAtomicClosed(t, f, f.stages[0])
		if err := replaceFile(src, dst); err != nil {
			return err
		}
		replacement, err := os.OpenFile(src, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		n, writeErr := replacement.Write([]byte("replacement object"))
		if n != len("replacement object") {
			writeErr = errors.Join(writeErr, io.ErrShortWrite)
		}
		syncErr := replacement.Sync()
		closeErr := replacement.Close()
		if closeErr != nil {
			f.preserve.Store(true)
		}
		return errors.Join(writeErr, syncErr, closeErr)
	}
	if err := atomicWrite(f.destination, []byte("published"), ops); err != nil {
		t.Fatal(err)
	}
	assertAtomicBytes(t, f.destination, []byte("published"))
	assertAtomicBytes(t, f.stages[0].Name(), []byte("replacement object"))
}

func TestAtomicWritePanicPreservesOriginalAndClosesActualStage(t *testing.T) {
	for _, cofault := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "close"}[cofault], func(t *testing.T) {
			f := newAtomicWriteFixture(t)
			original := &struct{ label string }{"PRIVATE_ATOMIC_PANIC"}
			ops := f.ops(func(s *atomicWriteTestStage) {
				s.panicAfterWrite = original
				if cofault {
					s.closeFault = errors.New("PRIVATE_PANIC_CLOSE")
				}
			})
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_ = atomicWrite(f.destination, []byte("written before panic"), ops)
			}()
			if recovered != original {
				t.Fatal("original body panic replaced or swallowed")
			}
			assertAtomicClosed(t, f, f.stages[0])
			assertAtomicBytes(t, f.stages[0].Name(), []byte("written before panic"))
			assertAtomicBytes(t, f.destination, []byte("old destination"))
		})
	}
}

func TestAtomicWriteBlockedCloseRetainsScopeBeforePublication(t *testing.T) {
	f := newAtomicWriteFixture(t)
	entered, gate, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	var err error
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			f.preserve.Store(true)
			t.Error("unconfirmed atomic owner retained")
		}
	})
	ops := f.ops(func(s *atomicWriteTestStage) { s.beforeClose = func() { close(entered); <-gate } })
	go func() { defer close(done); err = atomicWrite(f.destination, []byte("after release"), ops) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		f.preserve.Store(true)
		t.Fatal("owned Close did not enter")
	}
	select {
	case <-done:
		t.Fatal("blocked actual Close scope was abandoned")
	default:
	}
	assertAtomicBytes(t, f.destination, []byte("old destination"))
	release()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		f.preserve.Store(true)
		t.Fatal("owned Close did not finish")
	}
	if err != nil {
		t.Fatal(err)
	}
	assertAtomicClosed(t, f, f.stages[0])
	assertAtomicBytes(t, f.destination, []byte("after release"))
}
