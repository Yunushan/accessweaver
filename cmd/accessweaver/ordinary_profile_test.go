package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

type ordinaryOwnedInput struct {
	file                  *os.File
	readCause, closeCause error
	panicValue            any
	closes, readBytes     int
	actualClose           error
}

func (r *ordinaryOwnedInput) Read(p []byte) (int, error) {
	n, err := r.file.Read(p)
	r.readBytes += n
	if r.panicValue != nil {
		panic(r.panicValue)
	}
	if r.readCause != nil {
		return n, errors.Join(err, r.readCause)
	}
	return n, err
}
func (r *ordinaryOwnedInput) Close() error {
	r.closes++
	r.actualClose = r.file.Close()
	if r.actualClose != nil {
		return r.actualClose
	}
	return r.closeCause
}
func ordinaryProfileFixture(t *testing.T, data []byte) *ordinaryOwnedInput {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-ordinary-profile-")
	if err != nil {
		t.Fatal("owned profile root unavailable")
	}
	identity, err := os.Lstat(root)
	if err != nil {
		t.Fatal("owned root identity unavailable; root retained")
	}
	path := filepath.Join(root, "source.json")
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("owned profile bytes unavailable; root retained")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("owned profile reader unavailable; root retained")
	}
	input := &ordinaryOwnedInput{file: file}
	t.Cleanup(func() {
		if input.closes == 0 {
			input.closes++
			input.actualClose = file.Close()
		}
		if input.actualClose != nil {
			t.Error("unconfirmed profile reader retained")
			return
		}
		current, err := os.Lstat(root)
		if err != nil || !os.SameFile(identity, current) {
			t.Error("changed fixture retained")
			return
		}
		if os.RemoveAll(root) != nil {
			t.Error("owned fixture cleanup failed")
		}
	})
	return input
}
func ordinaryProfileData(t *testing.T) []byte {
	t.Helper()
	p := profile.New("ordinary-profile", "PRIVATE_PROFILE_NAME", "byedpi")
	p.Notes = "PRIVATE_PROFILE_NOTES"
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal("source profile encode failed")
	}
	return data
}

func TestOrdinaryProfileInputCompletionBeforeImport(t *testing.T) {
	for _, mode := range []string{"clean", "read", "close", "both", "eof-cofailure", "schema", "schema-close"} {
		t.Run(mode, func(t *testing.T) {
			data := ordinaryProfileData(t)
			if mode == "schema" || mode == "schema-close" {
				data = []byte("{INVALID_PRIVATE_JSON")
			}
			input := ordinaryProfileFixture(t, data)
			readCause := errors.New("PRIVATE_READ_CAUSE")
			closeCause := &os.PathError{Op: "PRIVATE_CLOSE", Path: "PRIVATE_SOURCE_PATH", Err: errors.New("PRIVATE_CLOSE_CAUSE")}
			if mode == "read" || mode == "both" {
				input.readCause = readCause
			}
			if mode == "eof-cofailure" {
				input.readCause = errors.Join(io.EOF, readCause)
			}
			if mode == "close" || mode == "both" || mode == "schema-close" {
				input.closeCause = closeCause
			}
			guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
			store, err := profile.NewStoreWithGuard(filepath.Join(filepath.Dir(input.file.Name()), "state"), guard)
			if err != nil {
				t.Fatal("owned store unavailable")
			}
			var out bytes.Buffer
			saves := 0
			load := func(string) (profile.Profile, error) { return decodeOwnedOrdinaryProfile(input) }
			save := func(p profile.Profile) error {
				saves++
				if n, e := input.file.Read(make([]byte, 1)); n != 0 || !errors.Is(e, os.ErrClosed) {
					return errors.New("source reader still open before Save")
				}
				return store.Save(p)
			}
			err = ordinaryProfileCommand(input.file.Name(), &out, load, save)
			if input.closes != 1 || input.actualClose != nil || input.readBytes == 0 {
				t.Fatal("physical source read/Close not confirmed exactly once")
			}
			if mode == "clean" {
				if err != nil || saves != 1 || out.String() != "Imported: ordinary-profile\n" {
					t.Fatal("confirmed import acknowledgement changed")
				}
				p, e := store.Get("ordinary-profile")
				if e != nil || p.Name != "PRIVATE_PROFILE_NAME" || p.Notes != "PRIVATE_PROFILE_NOTES" {
					t.Fatal("actual saved profile changed")
				}
				return
			}
			if err == nil || saves != 0 || out.Len() != 0 {
				t.Fatal("unconfirmed input reached Save or success output")
			}
			if _, e := store.Get("ordinary-profile"); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("failed input published selected profile")
			}
			if mode == "schema" {
				var syntax *json.SyntaxError
				if !errors.As(err, &syntax) || errors.Is(err, errOrdinaryProfileInput) {
					t.Fatal("clean schema error lost original type")
				}
				return
			}
			if !errors.Is(err, errOrdinaryProfileInput) || err.Error() != errOrdinaryProfileInput.Error() {
				t.Fatal("input completion failure exposed private details")
			}
			if input.readCause != nil && !errors.Is(err, readCause) {
				t.Fatal("original read cofailure lost")
			}
			if input.closeCause != nil && !errors.Is(err, closeCause) {
				t.Fatal("original Close cofailure lost")
			}
			if mode == "schema-close" {
				var syntax *json.SyntaxError
				if !errors.As(err, &syntax) {
					t.Fatal("schema cause lost behind Close cofailure")
				}
			}
		})
	}
}

func TestOrdinaryProfileInputBoundsAndAliases(t *testing.T) {
	for _, extra := range []int{0, 1} {
		label := "exact"
		if extra != 0 {
			label = "oversize"
		}
		t.Run(label, func(t *testing.T) {
			data := ordinaryProfileData(t)
			data = append(data, bytes.Repeat([]byte(" "), (1<<20)+extra-len(data))...)
			input := ordinaryProfileFixture(t, data)
			p, err := decodeOwnedOrdinaryProfile(input)
			if input.closes != 1 || input.actualClose != nil || input.readBytes > (1<<20)+1 {
				t.Fatal("actual input cap or Close lost")
			}
			if extra == 0 {
				if err != nil || p.ID != "ordinary-profile" {
					t.Fatal("exact input bound refused")
				}
			} else if err == nil || !reflect.DeepEqual(p, profile.Profile{}) {
				t.Fatal("oversized input released a profile")
			}
		})
	}
	t.Run("relative", func(t *testing.T) {
		input := ordinaryProfileFixture(t, ordinaryProfileData(t))
		t.Chdir(filepath.Dir(input.file.Name()))
		p, err := readOrdinaryProfile("source.json")
		if err != nil || p.ID != "ordinary-profile" {
			t.Fatal("relative source compatibility changed")
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("alias", func(t *testing.T) {
			input := ordinaryProfileFixture(t, ordinaryProfileData(t))
			alias := filepath.Join(filepath.Dir(input.file.Name()), "alias.json")
			if os.Symlink(input.file.Name(), alias) != nil {
				t.Fatal("owned alias unavailable")
			}
			p, err := readOrdinaryProfile(alias)
			if err != nil || p.ID != "ordinary-profile" {
				t.Fatal("followed input alias compatibility changed")
			}
		})
	}
}

func TestOrdinaryProfileInputPanicClosesOriginalReader(t *testing.T) {
	input := ordinaryProfileFixture(t, ordinaryProfileData(t))
	original := &struct{ tag string }{"PRIVATE_PANIC"}
	input.panicValue = original
	var recovered any
	func() { defer func() { recovered = recover() }(); _, _ = decodeOwnedOrdinaryProfile(input) }()
	if recovered != original || input.closes != 1 || input.actualClose != nil {
		t.Fatal("read panic lost original value or actual Close")
	}
	if n, e := input.file.Read(make([]byte, 1)); n != 0 || !errors.Is(e, os.ErrClosed) {
		t.Fatal("panicking reader remained open")
	}
}

type ordinaryNoticeWriter struct {
	write  func([]byte) (int, error)
	closes int
}

func (w *ordinaryNoticeWriter) Write(p []byte) (int, error) { return w.write(p) }
func (w *ordinaryNoticeWriter) Close() error                { w.closes++; return nil }

func TestOrdinaryProfileOutputFailureKeepsActualSavedState(t *testing.T) {
	for _, mode := range []string{"short", "negative", "excess", "cause-after-write", "closed-file"} {
		t.Run(mode, func(t *testing.T) {
			input := ordinaryProfileFixture(t, ordinaryProfileData(t))
			guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
			store, err := profile.NewStoreWithGuard(filepath.Join(filepath.Dir(input.file.Name()), "state"), guard)
			if err != nil {
				t.Fatal("owned store unavailable")
			}
			cause := &os.PathError{Op: "PRIVATE_OUTPUT", Path: "PRIVATE_SINK_PATH", Err: errors.New("PRIVATE_SINK_CAUSE")}
			var ack bytes.Buffer
			writes, saves := 0, 0
			var closed *os.File
			if mode == "closed-file" {
				closed, err = os.CreateTemp(filepath.Dir(input.file.Name()), "sink-")
				if err != nil || closed.Close() != nil {
					t.Fatal("owned closed sink unavailable")
				}
			}
			out := &ordinaryNoticeWriter{write: func(p []byte) (int, error) {
				writes++
				switch mode {
				case "short":
					return len(p) - 1, nil
				case "negative":
					return -1, nil
				case "excess":
					return len(p) + 1, nil
				case "cause-after-write":
					n, e := ack.Write(p)
					if e != nil {
						return n, e
					}
					return n, cause
				default:
					return closed.Write(p)
				}
			}}
			load := func(string) (profile.Profile, error) { return decodeOwnedOrdinaryProfile(input) }
			err = ordinaryProfileCommand(input.file.Name(), out, load, func(p profile.Profile) error { saves++; return store.Save(p) })
			if !errors.Is(err, errOrdinaryImportOutput) || err.Error() != errOrdinaryImportOutput.Error() || saves != 1 || writes != 1 || out.closes != 0 {
				t.Fatal("failed acknowledgement retried mutation, closed borrowed output or exposed details")
			}
			if mode == "short" || mode == "negative" || mode == "excess" {
				if !errors.Is(err, io.ErrShortWrite) {
					t.Fatal("invalid acknowledgement count not retained")
				}
			}
			if mode == "cause-after-write" && (!errors.Is(err, cause) || ack.String() != "Imported: ordinary-profile\n") {
				t.Fatal("actual acknowledgement and later cofailure lost")
			}
			if mode == "closed-file" && !errors.Is(err, os.ErrClosed) {
				t.Fatal("native closed sink cause lost")
			}
			p, e := store.Get("ordinary-profile")
			if e != nil || p.Notes != "PRIVATE_PROFILE_NOTES" {
				t.Fatal("output failure rolled back or lost actual import")
			}
		})
	}
}

func TestOrdinaryProfileValidationAndSaveRefusalOutput(t *testing.T) {
	input := ordinaryProfileFixture(t, ordinaryProfileData(t))
	var output bytes.Buffer
	err := ordinaryProfileCommand(input.file.Name(), &output, func(string) (profile.Profile, error) { return decodeOwnedOrdinaryProfile(input) }, nil)
	if err != nil || output.String() != "Valid profile: ordinary-profile\n" || input.closes != 1 {
		t.Fatal("confirmed validation output changed")
	}
	second := ordinaryProfileFixture(t, ordinaryProfileData(t))
	output.Reset()
	refusal := errors.New("source refuses Save")
	err = ordinaryProfileCommand(second.file.Name(), &output, func(string) (profile.Profile, error) { return decodeOwnedOrdinaryProfile(second) }, func(profile.Profile) error { return refusal })
	if err != refusal || output.Len() != 0 || second.closes != 1 {
		t.Fatal("Save refusal lost original error or emitted success")
	}
}

type ordinaryGatedOwner struct {
	owner   io.Closer
	entered chan struct{}
	release <-chan struct{}
	closes  int
	cause   error
}

func (c *ordinaryGatedOwner) Close() error {
	c.closes++
	if c.entered != nil {
		close(c.entered)
		<-c.release
	}
	if err := c.owner.Close(); err != nil {
		return err
	}
	return c.cause
}

func TestOrdinaryCommandCleanupRetainsControllerUntilActualClose(t *testing.T) {
	input := ordinaryProfileFixture(t, ordinaryProfileData(t))
	root := filepath.Dir(input.file.Name())
	path := filepath.Join(root, "controller.lock")
	lease, err := filelock.TryAcquire(path)
	if err != nil {
		t.Fatal("owned controller unavailable")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	body := errors.New("PRIVATE_BODY_CAUSE")
	controllerCause := errors.New("PRIVATE_CONTROLLER_CLOSE_CAUSE")
	runtimeCause := errors.New("PRIVATE_RUNTIME_CLOSE_CAUSE")
	controller := &ordinaryGatedOwner{owner: lease, entered: entered, release: release, cause: controllerCause}
	runtimeOwner := &ordinaryGatedOwner{owner: input, cause: runtimeCause}
	var once sync.Once
	joined := false
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		if !joined {
			<-done
		}
	})
	go func() {
		operation := func() (failure error) {
			defer func() { failure = closeOrdinaryCommandOwner(failure, runtimeOwner) }()
			defer func() { failure = closeOrdinaryCommandOwner(failure, controller) }()
			return body
		}
		done <- operation()
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("controller never entered actual Close")
	}
	other, busy := filelock.TryAcquire(path)
	if other != nil {
		closeErr := other.Close()
		if closeErr != nil {
			t.Fatal("unexpected second controller Close failed")
		}
		t.Fatal("controller ownership released before Close returned")
	}
	if !errors.Is(busy, filelock.ErrBusy) || runtimeOwner.closes != 0 {
		t.Fatal("controller/runtime scope order changed")
	}
	select {
	case <-done:
		joined = true
		t.Fatal("scope returned while actual controller Close blocked")
	default:
	}
	once.Do(func() { close(release) })
	err = <-done
	joined = true
	if !errors.Is(err, errOrdinaryCommandCleanup) || !errors.Is(err, body) || !errors.Is(err, controllerCause) || !errors.Is(err, runtimeCause) || err.Error() != errOrdinaryCommandCleanup.Error() {
		t.Fatal("outer cleanup lost body or Close cofactors or exposed private details")
	}
	if controller.closes != 1 || runtimeOwner.closes != 1 || input.closes != 1 || input.actualClose != nil {
		t.Fatal("actual owner Close not completed once")
	}
	fresh, e := filelock.TryAcquire(path)
	if e != nil || fresh == nil {
		t.Fatal("actual controller release was not confirmed")
	}
	if fresh.Close() != nil {
		t.Fatal("fresh owned controller Close failed")
	}
}

func TestOrdinaryCommandCleanCleanupPreservesBodyAndPanic(t *testing.T) {
	for _, panicBody := range []bool{false, true} {
		label := "error"
		if panicBody {
			label = "panic"
		}
		t.Run(label, func(t *testing.T) {
			input := ordinaryProfileFixture(t, ordinaryProfileData(t))
			body := errors.New("PRIVATE_BODY_CAUSE")
			original := &struct{ tag string }{"PRIVATE_PANIC"}
			var failure error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				failure = func() (err error) {
					defer func() { err = closeOrdinaryCommandOwner(err, input) }()
					if panicBody {
						panic(original)
					}
					return body
				}()
			}()
			if input.closes != 1 || input.actualClose != nil {
				t.Fatal("actual enclosing owner Close lost")
			}
			if panicBody {
				if recovered != original {
					t.Fatal("original command panic replaced")
				}
			} else if recovered != nil || failure != body {
				t.Fatal("clean cleanup changed original command failure")
			}
		})
	}
}

func TestOrdinaryValidationOutputFailureCannotClaimImport(t *testing.T) {
	input := ordinaryProfileFixture(t, ordinaryProfileData(t))
	out := &ordinaryNoticeWriter{write: func(p []byte) (int, error) { return len(p) - 1, nil }}
	err := ordinaryProfileCommand(input.file.Name(), out, func(string) (profile.Profile, error) { return decodeOwnedOrdinaryProfile(input) }, nil)
	if !errors.Is(err, errOrdinaryValidationOutput) || !errors.Is(err, io.ErrShortWrite) || errors.Is(err, errOrdinaryImportOutput) || out.closes != 0 || input.closes != 1 {
		t.Fatal("validation output failure claimed import or lost its ownership contract")
	}
}

func TestOrdinaryCleanupFailureAfterSuccessfulBodyIsNotSuccess(t *testing.T) {
	input := ordinaryProfileFixture(t, ordinaryProfileData(t))
	cause := &os.PathError{Op: "PRIVATE_CLOSE", Path: "PRIVATE_OWNER_PATH", Err: errors.New("PRIVATE_CLOSE_CAUSE")}
	input.closeCause = cause
	err := closeOrdinaryCommandOwner(nil, input)
	if !errors.Is(err, errOrdinaryCommandCleanup) || !errors.Is(err, cause) || err.Error() != errOrdinaryCommandCleanup.Error() || input.closes != 1 || input.actualClose != nil {
		t.Fatal("successful body hid actual Close cofailure")
	}
}

func TestOrdinaryExecuteActualValidationAndImport(t *testing.T) {
	input := ordinaryProfileFixture(t, ordinaryProfileData(t))
	source := input.file.Name()
	if input.Close() != nil || input.actualClose != nil {
		t.Fatal("fixture source Close unconfirmed")
	}
	state := filepath.Join(filepath.Dir(source), "state")
	t.Setenv("ACCESSWEAVER_HOME", state)
	if err := execute([]string{"validate", source}); err != nil {
		t.Fatal("actual validation command failed")
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("validation created a profile store")
	}
	if err := execute([]string{"import", source}); err != nil {
		t.Fatal("actual import command failed")
	}
	guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	store, err := profile.NewStoreWithGuard(state, guard)
	if err != nil {
		t.Fatal("actual import store unavailable")
	}
	saved, err := store.Get("ordinary-profile")
	if err != nil || saved.Name != "PRIVATE_PROFILE_NAME" || saved.Notes != "PRIVATE_PROFILE_NOTES" {
		t.Fatal("actual command import changed profile bytes")
	}
	controller, err := filelock.TryAcquire(filepath.Join(state, ".controller.lock"))
	if err != nil || controller == nil {
		t.Fatal("actual command retained controller ownership")
	}
	if controller.Close() != nil {
		t.Fatal("fresh controller Close failed")
	}
}
