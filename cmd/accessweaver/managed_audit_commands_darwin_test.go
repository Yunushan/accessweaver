//go:build darwin && (amd64 || arm64)

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/api"
	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
	"golang.org/x/sys/unix"
)

var darwinCommandCaseIDs = []string{
	"signed-required-audit-admission", "initialize-import-retained-head",
	"audited-private-http-desktop", "read-only-export-verify",
	"current-recorded-export-key-boundary", "actual-output-alias-admission",
	"full-journal-reservation-refusal", "approved-recorded-foreground-run",
	"recorded-foreground-output-cancellation-drain", "private-command-workspace-cleanup",
}
var darwinCommandCloseFailure bool

const darwinCommandPolicy = "/Library/Preferences/AccessWeaver/installation.json"
const darwinCommandAcceptance = "/Library/Preferences/AccessWeaver/acceptance.json"
const darwinCommandCoordination = "/Library/Preferences/.accessweaver-policy.lock"

type darwinCommandObject struct {
	path         string
	file, parent *os.File
	id           fileidentity.ID
	directory    bool
}
type darwinCommandWorker struct {
	base, directory, state, profilePath, engine, home string
	uid                                               uint32
	start, head                                       audit.Checkpoint
	p                                                 profile.Profile
	holdProfile                                       profile.Profile
	owner                                             *darwinCommandWorker
	objects                                           []*darwinCommandObject
	parent                                            *os.File
	ctx                                               context.Context
	counter                                           uint32
	preserve                                          bool
	closed                                            bool
	closeErr                                          error
	active                                            *atomic.Int32
}

func (w *darwinCommandWorker) manifest() *darwinCommandWorker {
	if w.owner != nil {
		return w.owner
	}
	return w
}
func darwinCommandRead(path string, limit int64) ([]byte, error) {
	return darwinOrdinaryRead(path, limit)
}
func darwinCommandReadDefault(path string) ([]byte, error) {
	return darwinCommandRead(path, audit.MaxJournalBytes)
}
func darwinCommandReadSource(w *darwinCommandWorker, path string) ([]byte, error) {
	if path == w.engine {
		return darwinCommandRead(path, 128<<20)
	}
	return darwinCommandReadDefault(path)
}
func darwinCommandFilePrivate(file *os.File, directory bool, uid uint32) error {
	info, err := file.Stat()
	if err != nil {
		return errDarwinOrdinary
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Flags != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errDarwinOrdinary
	}
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
		if !info.IsDir() {
			return errDarwinOrdinary
		}
	} else if !info.Mode().IsRegular() || stat.Nlink != 1 {
		return errDarwinOrdinary
	}
	if info.Mode().Perm() != mode || darwintrust.CheckPersistent(file) != nil || darwintrust.CheckEmptyACL(file) != nil {
		return errDarwinOrdinary
	}
	return nil
}
func (w *darwinCommandWorker) parentFor(path string) (*os.File, error) {
	root := w.manifest()
	if path == root.base {
		return root.parent, nil
	}
	for _, object := range root.objects {
		if object.directory && object.path == filepath.Dir(path) {
			return object.file, nil
		}
	}
	return nil, errDarwinOrdinary
}
func darwinCommandNamed(parent *os.File, name string) (fileidentity.ID, error) {
	raw, err := parent.SyscallConn()
	if err != nil {
		return fileidentity.ID{}, errDarwinOrdinary
	}
	var stat unix.Stat_t
	var nativeErr error
	err = raw.Control(func(fd uintptr) { nativeErr = unix.Fstatat(int(fd), name, &stat, unix.AT_SYMLINK_NOFOLLOW) })
	if err != nil || nativeErr != nil || stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fileidentity.ID{}, errDarwinOrdinary
	}
	// The actual fileidentity helper remains the authority for held objects;
	// this checked name is compared through a fresh descriptor below.
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
		flags |= unix.O_DIRECTORY
	} else if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fileidentity.ID{}, errDarwinOrdinary
	}
	var handle int = -1
	if raw.Control(func(fd uintptr) { handle, nativeErr = unix.Openat(int(fd), name, flags, 0) }) != nil || nativeErr != nil || handle < 0 {
		return fileidentity.ID{}, errDarwinOrdinary
	}
	file := os.NewFile(uintptr(handle), "ordinary-command-name")
	id, identityErr := fileidentity.FromFile(file)
	closeErr := file.Close()
	if identityErr != nil || closeErr != nil {
		return fileidentity.ID{}, errDarwinOrdinary
	}
	return id.ID, nil
}
func (w *darwinCommandWorker) record(path string) error {
	root := w.manifest()
	if path != root.base && !strings.HasPrefix(path, root.base+string(os.PathSeparator)) {
		return errDarwinOrdinary
	}
	for _, object := range root.objects {
		if object.path == path {
			return w.same(object)
		}
	}
	if len(root.objects) >= 2048 {
		return errDarwinOrdinary
	}
	parent, err := w.parentFor(path)
	if err != nil || parent == nil {
		return errDarwinOrdinary
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errDarwinOrdinary
	}
	directory := info.IsDir()
	if !directory && !info.Mode().IsRegular() {
		return errDarwinOrdinary
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if directory {
		flags |= unix.O_DIRECTORY
	}
	raw, err := parent.SyscallConn()
	if err != nil {
		return errDarwinOrdinary
	}
	var fd int = -1
	var nativeErr error
	if raw.Control(func(parentFD uintptr) { fd, nativeErr = unix.Openat(int(parentFD), filepath.Base(path), flags, 0) }) != nil || nativeErr != nil || fd < 0 {
		return errDarwinOrdinary
	}
	file := os.NewFile(uintptr(fd), "ordinary-command-owned")
	id, identityErr := fileidentity.FromFile(file)
	if identityErr != nil || darwinCommandFilePrivate(file, directory, w.uid) != nil {
		if file.Close() != nil {
			darwinCommandCloseFailure = true
		}
		return errDarwinOrdinary
	}
	object := &darwinCommandObject{path: path, file: file, parent: parent, id: id.ID, directory: directory}
	root.objects = append(root.objects, object)
	return w.same(object)
}
func (w *darwinCommandWorker) same(object *darwinCommandObject) error {
	if object == nil || object.file == nil || object.parent == nil || darwinCommandFilePrivate(object.file, object.directory, w.uid) != nil {
		return errDarwinOrdinary
	}
	id, err := fileidentity.FromFile(object.file)
	named, nameErr := darwinCommandNamed(object.parent, filepath.Base(object.path))
	if err != nil || nameErr != nil || id.ID != object.id || named != object.id {
		return errDarwinOrdinary
	}
	return nil
}
func (w *darwinCommandWorker) forget(path string) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errDarwinOrdinary
	}
	root := w.manifest()
	for index, object := range root.objects {
		if object.path == path {
			if object.file.Close() != nil {
				darwinCommandCloseFailure = true
				return errDarwinOrdinary
			}
			root.objects = append(root.objects[:index], root.objects[index+1:]...)
			return nil
		}
	}
	return errDarwinOrdinary
}
func (w *darwinCommandWorker) remove(path string) error {
	root := w.manifest()
	for _, object := range root.objects {
		if object.path == path {
			if w.same(object) != nil {
				return errDarwinOrdinary
			}
			flags := 0
			if object.directory {
				flags = unix.AT_REMOVEDIR
			}
			raw, err := object.parent.SyscallConn()
			if err != nil {
				return errDarwinOrdinary
			}
			var nativeErr error
			if raw.Control(func(fd uintptr) { nativeErr = unix.Unlinkat(int(fd), filepath.Base(path), flags) }) != nil || nativeErr != nil {
				return errDarwinOrdinary
			}
			return w.forget(path)
		}
	}
	return errDarwinOrdinary
}
func (w *darwinCommandWorker) mkdirPrivate(path string) error {
	if os.Mkdir(path, 0700) != nil {
		return errDarwinOrdinary
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errDarwinOrdinary
	}
	file := os.NewFile(uintptr(fd), "ordinary-command-new-directory")
	aclErr := darwintrust.ResetCreatedACL(file)
	modeErr := file.Chmod(0700)
	closeErr := file.Close()
	if aclErr != nil || modeErr != nil || closeErr != nil {
		if closeErr != nil {
			darwinCommandCloseFailure = true
		}
		return errDarwinOrdinary
	}
	return w.record(path)
}
func (w *darwinCommandWorker) ownFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return errDarwinOrdinary
	}
	aclErr := darwintrust.ResetCreatedACL(file)
	modeErr := file.Chmod(0600)
	var recordErr, writeErr, syncErr error
	if aclErr == nil && modeErr == nil {
		recordErr = w.record(path)
		if recordErr == nil {
			var n int
			n, writeErr = file.Write(data)
			if n != len(data) {
				writeErr = io.ErrShortWrite
			}
			if writeErr == nil && len(data) > 0 {
				syncErr = darwinCommandSync(file)
			}
		}
	}
	closeErr := file.Close()
	if closeErr != nil {
		darwinCommandCloseFailure = true
	}
	if aclErr != nil || modeErr != nil || recordErr != nil || writeErr != nil || syncErr != nil || closeErr != nil {
		return errDarwinOrdinary
	}
	return nil
}
func darwinCommandSync(file *os.File) error {
	if file.Sync() != nil {
		return errDarwinOrdinary
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return errDarwinOrdinary
	}
	var nativeErr error
	if raw.Control(func(fd uintptr) { _, nativeErr = unix.FcntlInt(fd, unix.F_FULLFSYNC, 0) }) != nil || nativeErr != nil {
		return errDarwinOrdinary
	}
	return nil
}
func (w *darwinCommandWorker) put(path string, data []byte) error {
	for _, object := range w.manifest().objects {
		if object.path == path {
			if object.directory || w.same(object) != nil {
				return errDarwinOrdinary
			}
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				return errDarwinOrdinary
			}
			id, idErr := fileidentity.FromFile(file)
			var n int
			var writeErr, truncateErr, syncErr error
			if idErr == nil && id.ID == object.id {
				n, writeErr = file.WriteAt(data, 0)
				truncateErr = file.Truncate(int64(len(data)))
				syncErr = darwinCommandSync(file)
			} else {
				writeErr = errDarwinOrdinary
			}
			closeErr := file.Close()
			if closeErr != nil {
				darwinCommandCloseFailure = true
			}
			if idErr != nil || writeErr != nil || truncateErr != nil || syncErr != nil || closeErr != nil || n != len(data) || w.same(object) != nil {
				return errDarwinOrdinary
			}
			return nil
		}
	}
	return w.ownFile(path, data)
}
func (w *darwinCommandWorker) privateCapture() (*os.File, error) {
	root := w.manifest()
	root.counter++
	path := filepath.Join(root.base, "capture-"+strconv.FormatUint(uint64(root.counter), 10)+".bin")
	if w.ownFile(path, nil) != nil {
		return nil, errDarwinOrdinary
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	return file, nil
}
func (w *darwinCommandWorker) command(args []string, stdout, stderr *os.File) ([]byte, []byte, error) {
	return w.commandHome(w.state, args, stdout, stderr)
}
func (w *darwinCommandWorker) commandHome(home string, args []string, stdout, stderr *os.File) (out, notice []byte, failure error) {
	if w.ctx.Err() != nil || home == "" {
		return nil, nil, errDarwinOrdinary
	}
	root := w.manifest()
	if root.active != nil {
		root.active.Add(1)
		defer root.active.Add(-1)
	}
	previousHome, hadHome := os.LookupEnv("ACCESSWEAVER_HOME")
	if os.Setenv("ACCESSWEAVER_HOME", home) != nil {
		return nil, nil, errDarwinOrdinary
	}
	defer func() {
		var err error
		if hadHome {
			err = os.Setenv("ACCESSWEAVER_HOME", previousHome)
		} else {
			err = os.Unsetenv("ACCESSWEAVER_HOME")
		}
		if err != nil {
			failure = errDarwinOrdinary
		}
	}()
	var ownOut, ownErr bool
	var err error
	if stdout == nil {
		stdout, err = w.privateCapture()
		if err != nil {
			return nil, nil, err
		}
		ownOut = true
	}
	if stderr == nil {
		stderr, err = w.privateCapture()
		if err != nil {
			if ownOut && stdout.Close() != nil {
				darwinCommandCloseFailure = true
			}
			return nil, nil, err
		}
		ownErr = true
	}
	previousOut, previousErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	defer func() { os.Stdout, os.Stderr = previousOut, previousErr }()
	commandErr := execute(args)
	os.Stdout, os.Stderr = previousOut, previousErr
	read := func(file *os.File) ([]byte, error) {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, errDarwinOrdinary
		}
		data, err := io.ReadAll(io.LimitReader(file, audit.MaxJournalBytes+1))
		if err != nil || len(data) > audit.MaxJournalBytes {
			clear(data)
			return nil, errDarwinOrdinary
		}
		return data, nil
	}
	if ownOut {
		out, err = read(stdout)
		closeErr := stdout.Close()
		removeErr := w.remove(stdout.Name())
		if closeErr != nil {
			darwinCommandCloseFailure = true
		}
		if err != nil || closeErr != nil || removeErr != nil {
			failure = errDarwinOrdinary
		}
	}
	if ownErr {
		notice, err = read(stderr)
		closeErr := stderr.Close()
		removeErr := w.remove(stderr.Name())
		if closeErr != nil {
			darwinCommandCloseFailure = true
		}
		if err != nil || closeErr != nil || removeErr != nil {
			failure = errDarwinOrdinary
		}
	}
	if failure != nil {
		return out, notice, failure
	}
	return out, notice, commandErr
}
func darwinCommandMetadata(w *darwinCommandWorker, outputs ...[]byte) bool {
	private := [][]byte{[]byte(w.manifest().base), []byte(w.p.ID), []byte(w.p.Name), []byte(w.engine), []byte("\"uid\":"), []byte("\"gid\":")}
	key, err := darwinCommandRead(filepath.Join(w.directory, ".actor-key"), 4096)
	if err == nil {
		defer clear(key)
		private = append(private, key)
		if len(key) >= 32 {
			private = append(private, key[len(key)-32:])
		}
	} else if _, probe := os.Lstat(filepath.Join(w.directory, ".actor-key")); !errors.Is(probe, os.ErrNotExist) {
		return false
	}
	for _, output := range outputs {
		for _, value := range private {
			if len(value) > 0 && bytes.Contains(output, value) {
				return false
			}
		}
	}
	return true
}
func (w *darwinCommandWorker) sources() map[string][]byte {
	result := map[string][]byte{}
	for _, path := range []string{w.profilePath, filepath.Join(w.directory, "events.journal"), filepath.Join(w.directory, ".actor-key"), filepath.Join(w.base, "genesis.json"), filepath.Join(w.base, "head.json"), darwinCommandPolicy, darwinCommandAcceptance} {
		data, err := darwinCommandReadDefault(path)
		if err != nil {
			return nil
		}
		result[path] = data
	}
	return result
}
func (w *darwinCommandWorker) preserved(before map[string][]byte) bool {
	if before == nil {
		return false
	}
	for path, data := range before {
		actual, err := darwinCommandReadSource(w, path)
		if err != nil || !bytes.Equal(actual, data) {
			clear(actual)
			return false
		}
		clear(actual)
	}
	return true
}
func (w *darwinCommandWorker) recordProducts() error {
	for _, name := range []string{".controller.lock", ".profiles.lock"} {
		path := filepath.Join(w.state, name)
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || w.record(path) != nil {
			return errDarwinOrdinary
		}
	}
	for _, name := range []string{"presets-initialized", "generated"} {
		if _, err := os.Lstat(filepath.Join(w.state, name)); !errors.Is(err, os.ErrNotExist) {
			return errDarwinOrdinary
		}
	}
	return nil
}
func (w *darwinCommandWorker) adoptProfile(saved profile.Profile) error {
	path := filepath.Join(w.state, "profiles", saved.ID+".json")
	data, err := darwinCommandReadDefault(path)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(data)
	actual, err := profile.Decode(bytes.NewReader(data))
	if err != nil || !reflect.DeepEqual(actual, saved) || actual.UpdatedAt.IsZero() {
		return errDarwinOrdinary
	}
	root := w.manifest()
	for index, object := range root.objects {
		if object.path == path {
			if object.file.Close() != nil {
				darwinCommandCloseFailure = true
				return errDarwinOrdinary
			}
			root.objects = append(root.objects[:index], root.objects[index+1:]...)
			break
		}
	}
	return w.record(path)
}
func (w *darwinCommandWorker) sweep() error {
	root := w.manifest()
	if root.active != nil && root.active.Load() != 0 {
		return errDarwinOrdinary
	}
	for len(root.objects) > 1 {
		object := root.objects[len(root.objects)-1]
		if object.path == root.base || w.remove(object.path) != nil {
			return errDarwinOrdinary
		}
	}
	return nil
}
func (w *darwinCommandWorker) close() error {
	root := w.manifest()
	if root.closed {
		return root.closeErr
	}
	root.closed = true
	if root.active != nil && root.active.Load() != 0 {
		root.closeErr = errDarwinOrdinary
		return root.closeErr
	}
	if root.preserve {
		// Every operation has returned, but its unexpected state is retained.
		// Release only our native handles; never unlink unknown/failed evidence.
		for index := len(root.objects) - 1; index >= 0; index-- {
			if root.objects[index].file.Close() != nil {
				darwinCommandCloseFailure = true
			}
		}
		if root.parent != nil && root.parent.Close() != nil {
			darwinCommandCloseFailure = true
		}
		root.parent = nil
		root.closeErr = errDarwinOrdinary
		return root.closeErr
	}
	var failure error
	for len(root.objects) > 0 {
		object := root.objects[len(root.objects)-1]
		if w.remove(object.path) != nil {
			failure = errDarwinOrdinary
			if object.file.Close() != nil {
				darwinCommandCloseFailure = true
			}
			root.objects = root.objects[:len(root.objects)-1]
		}
	}
	if root.parent != nil {
		if root.parent.Close() != nil {
			darwinCommandCloseFailure = true
		}
		root.parent = nil
	}
	if _, err := os.Lstat(root.base); !errors.Is(err, os.ErrNotExist) {
		failure = errDarwinOrdinary
	}
	if darwinCommandCloseFailure {
		failure = errDarwinOrdinary
	}
	root.closeErr = failure
	return failure
}

func darwinCommandCheckpoints(data []byte) ([]audit.Checkpoint, error) {
	if len(data) == 0 {
		return nil, errDarwinOrdinary
	}
	var result []audit.Checkpoint
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		checkpoint, err := audit.DecodeCheckpoint(append(append([]byte(nil), line...), '\n'))
		if err != nil || len(result) > 16 {
			return nil, errDarwinOrdinary
		}
		result = append(result, checkpoint)
	}
	return result, nil
}
func (w *darwinCommandWorker) newStream(label string) (*darwinCommandWorker, error) {
	root := w.manifest()
	child := &darwinCommandWorker{base: filepath.Join(root.base, label), uid: w.uid, engine: w.engine, p: w.p, owner: root, ctx: w.ctx}
	child.directory = filepath.Join(child.base, "journal")
	child.state = filepath.Join(child.base, "state")
	child.profilePath = filepath.Join(child.base, "profile.json")
	for _, path := range []string{child.base, child.directory, child.state, filepath.Join(child.state, "profiles")} {
		if child.directoryCreate(path) != nil {
			return nil, errDarwinOrdinary
		}
	}
	input, err := json.Marshal(child.p)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	if child.ownFile(child.profilePath, input) != nil {
		clear(input)
		return nil, errDarwinOrdinary
	}
	clear(input)
	output, _, err := child.command([]string{"audit", "initialize", "--directory", child.directory}, nil, nil)
	if err != nil {
		return nil, errDarwinOrdinary
	}
	checkpoints, err := darwinCommandCheckpoints(output)
	if err != nil || len(checkpoints) != 1 || checkpoints[0].Sequence != 0 || checkpoints[0].Producer.ActorClass != "user" || checkpoints[0].Producer.SourceCommit != buildinfo.Current().Commit || checkpoints[0].Producer.SourceState != "clean" {
		return nil, errDarwinOrdinary
	}
	child.start, child.head = checkpoints[0], checkpoints[0]
	for _, name := range []string{".actor-key", "events.journal"} {
		if child.record(filepath.Join(child.directory, name)) != nil {
			return nil, errDarwinOrdinary
		}
	}
	genesis, _ := audit.EncodeCheckpoint(child.start)
	if child.ownFile(filepath.Join(child.base, "genesis.json"), genesis) != nil || child.ownFile(filepath.Join(child.base, "head.json"), genesis) != nil {
		return nil, errDarwinOrdinary
	}
	return child, nil
}
func (w *darwinCommandWorker) directoryCreate(path string) error { return w.mkdirPrivate(path) }
func (w *darwinCommandWorker) writeHead() error {
	data, err := audit.EncodeCheckpoint(w.head)
	if err != nil {
		return errDarwinOrdinary
	}
	return w.put(filepath.Join(w.base, "head.json"), data)
}
func (w *darwinCommandWorker) importArgs() []string {
	return []string{"audit", "import", "--directory", w.directory, "--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json"), "--profile", w.profilePath}
}
func (w *darwinCommandWorker) exportArgs(recorded bool) []string {
	action := "export"
	if recorded {
		action = "export-recorded"
	}
	return []string{"audit", action, "--directory", w.directory, "--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json"), "--consent", "metadata-only"}
}
func (w *darwinCommandWorker) readSegment() ([]audit.Event, []byte, audit.Checkpoint, error) {
	raw, err := darwinCommandReadDefault(filepath.Join(w.directory, "events.journal"))
	if err != nil || len(raw) > audit.MaxJournalBytes {
		return nil, nil, audit.Checkpoint{}, errDarwinOrdinary
	}
	end := bytes.IndexByte(raw, '\n')
	if end < 0 {
		return nil, nil, audit.Checkpoint{}, errDarwinOrdinary
	}
	// Journal's first line is the retained genesis; remaining lines are JSONL.
	genesis, err := audit.DecodeCheckpoint(raw[:end+1])
	if err != nil || genesis != w.start {
		return nil, nil, audit.Checkpoint{}, errDarwinOrdinary
	}
	current := w.start
	var events []audit.Event
	for _, line := range bytes.Split(bytes.TrimSuffix(raw[end+1:], []byte{'\n'}), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var record struct {
			Event audit.Event `json:"event"`
		}
		if json.Unmarshal(line, &record) != nil {
			return nil, nil, audit.Checkpoint{}, errDarwinOrdinary
		}
		expected, next, err := audit.Append(current, record.Event)
		if err != nil || !bytes.Equal(expected, append(append([]byte(nil), line...), '\n')) {
			return nil, nil, audit.Checkpoint{}, errDarwinOrdinary
		}
		events = append(events, record.Event)
		current = next
	}
	if _, err := audit.VerifySegment(w.ctx, bytes.NewReader(raw[end+1:]), w.start, current); err != nil {
		return nil, nil, audit.Checkpoint{}, errDarwinOrdinary
	}
	return events, raw, current, nil
}

func (w *darwinCommandWorker) exportVerify(expected uint64) error {
	if w.writeHead() != nil {
		return errDarwinOrdinary
	}
	output, _, err := w.command(w.exportArgs(false), nil, nil)
	if err != nil {
		return errDarwinOrdinary
	}
	if !darwinCommandMetadata(w, output) {
		return errDarwinOrdinary
	}
	result, err := audit.VerifySegment(w.ctx, bytes.NewReader(output), w.start, w.head)
	if err != nil || result.Records != int(expected) {
		return errDarwinOrdinary
	}
	path := filepath.Join(w.base, "export.jsonl")
	if w.put(path, output) != nil {
		return errDarwinOrdinary
	}
	verified, _, err := w.command([]string{"audit", "verify", "--events", path, "--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json")}, nil, nil)
	if err != nil {
		return errDarwinOrdinary
	}
	var actual audit.Verification
	if json.Unmarshal(verified, &actual) != nil || actual.Records != int(expected) {
		return errDarwinOrdinary
	}
	return nil
}

func (w *darwinCommandWorker) importRoundTrip() error {
	s, err := w.newStream("import")
	if err != nil {
		return err
	}
	output, notice, err := s.command(s.importArgs(), nil, nil)
	if err != nil || len(notice) != 0 {
		return errDarwinOrdinary
	}
	checkpoints, err := darwinCommandCheckpoints(output)
	if err != nil || len(checkpoints) != 2 || checkpoints[0].Sequence != 1 || checkpoints[1].Sequence != 2 {
		return errDarwinOrdinary
	}
	s.head = checkpoints[1]
	store, err := profile.NewStore(s.state)
	if err != nil {
		return errDarwinOrdinary
	}
	saved, err := store.Get(s.p.ID)
	expected := s.p
	expected.UpdatedAt = saved.UpdatedAt
	if err != nil || !reflect.DeepEqual(saved, expected) || s.adoptProfile(saved) != nil || s.recordProducts() != nil {
		return errDarwinOrdinary
	}
	before := s.sources()
	originalProfile, err := darwinCommandReadDefault(filepath.Join(s.state, "profiles", saved.ID+".json"))
	if err != nil {
		return errDarwinOrdinary
	}
	output, notice, err = s.command(s.importArgs(), nil, nil) // Retained head is still genesis.
	if err == nil || len(output) != 0 || len(notice) != 0 || !s.preserved(before) {
		return errDarwinOrdinary
	}
	afterProfile, err := darwinCommandReadDefault(filepath.Join(s.state, "profiles", saved.ID+".json"))
	if err != nil || !bytes.Equal(originalProfile, afterProfile) {
		return errDarwinOrdinary
	}
	if s.writeHead() != nil {
		return errDarwinOrdinary
	}
	output, _, err = s.command(s.importArgs(), nil, nil) // Zero reviewed revision now conflicts.
	if !errors.Is(err, errAuditImportRefused) {
		return errDarwinOrdinary
	}
	observations, err := darwinCommandCheckpoints(output)
	if err != nil || len(observations) != 2 || observations[1].Sequence != 4 {
		return errDarwinOrdinary
	}
	s.head = observations[1]
	afterProfile, err = darwinCommandReadDefault(filepath.Join(s.state, "profiles", saved.ID+".json"))
	if err != nil || !bytes.Equal(originalProfile, afterProfile) {
		return errDarwinOrdinary
	}
	importEvents, _, importHead, importErr := s.readSegment()
	if importErr != nil || importHead != s.head || len(importEvents) != 4 {
		return errDarwinOrdinary
	}
	for i, event := range importEvents {
		expected := []string{"intent", "completed", "intent", "refused"}[i]
		if event.Action != "profile.import" || event.Outcome != expected || (i%2 == 1 && event.OperationID != importEvents[i-1].OperationID) {
			return errDarwinOrdinary
		}
	}
	if s.exportVerify(4) != nil {
		return errDarwinOrdinary
	}
	// A failed observation after initialization preserves both created files.
	failed := &darwinCommandWorker{base: filepath.Join(w.base, "initialize-output"), uid: w.uid, owner: w.manifest(), ctx: w.ctx}
	if failed.mkdirPrivate(failed.base) != nil {
		return errDarwinOrdinary
	}
	failed.directory = filepath.Join(failed.base, "journal")
	if failed.mkdirPrivate(failed.directory) != nil {
		return errDarwinOrdinary
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return errDarwinOrdinary
	}
	_ = reader.Close()
	_, _, commandErr := s.command([]string{"audit", "initialize", "--directory", failed.directory}, writer, nil)
	closeErr := writer.Close()
	if commandErr == nil || closeErr != nil {
		return errDarwinOrdinary
	}
	for _, name := range []string{".actor-key", "events.journal"} {
		if failed.record(filepath.Join(failed.directory, name)) != nil {
			return errDarwinOrdinary
		}
	}
	journal, err := darwinCommandReadDefault(filepath.Join(failed.directory, "events.journal"))
	keyBytes, keyErr := darwinCommandReadDefault(filepath.Join(failed.directory, ".actor-key"))
	if err != nil || keyErr != nil {
		return errDarwinOrdinary
	}
	_, _, commandErr = s.command([]string{"audit", "initialize", "--directory", failed.directory}, nil, nil)
	afterJournal, _ := darwinCommandReadDefault(filepath.Join(failed.directory, "events.journal"))
	afterKey, _ := darwinCommandReadDefault(filepath.Join(failed.directory, ".actor-key"))
	if commandErr == nil || !bytes.Equal(journal, afterJournal) || !bytes.Equal(keyBytes, afterKey) {
		return errDarwinOrdinary
	}
	return nil
}
func (w *darwinCommandWorker) historicalRoundTrip() error {
	s, err := w.newStream("readonly")
	if err != nil {
		return err
	}
	output, _, err := s.command(s.importArgs(), nil, nil)
	if err != nil {
		return errDarwinOrdinary
	}
	observations, err := darwinCommandCheckpoints(output)
	if err != nil || len(observations) != 2 {
		return errDarwinOrdinary
	}
	s.head = observations[1]
	store, err := profile.NewStore(s.state)
	if err != nil {
		return errDarwinOrdinary
	}
	saved, err := store.Get(s.p.ID)
	if err != nil || s.adoptProfile(saved) != nil || s.recordProducts() != nil || s.writeHead() != nil {
		return errDarwinOrdinary
	}
	before := s.sources()
	if s.exportVerify(2) != nil || !s.preserved(before) {
		return errDarwinOrdinary
	}
	absent := filepath.Join(s.base, "verify-must-not-create")
	verifyWorker := *s
	verifyWorker.state = absent
	_, _, err = verifyWorker.command([]string{"audit", "verify", "--events", filepath.Join(s.base, "export.jsonl"), "--from", filepath.Join(s.base, "genesis.json"), "--to", filepath.Join(s.base, "head.json")}, nil, nil)
	if err != nil || !s.preserved(before) {
		return errDarwinOrdinary
	}
	if _, err := fileidentity.FromPath(absent, false); !errors.Is(err, os.ErrNotExist) {
		return errDarwinOrdinary
	}
	return nil
}

func darwinHTTP(client *http.Client, method, address, token string, input any) (int, []byte, error) {
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return 0, nil, errDarwinOrdinary
		}
	}
	request, err := http.NewRequest(method, address, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errDarwinOrdinary
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("X-AccessWeaver-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, errDarwinOrdinary
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(data) >= 1<<20 {
		return 0, nil, errDarwinOrdinary
	}
	return response.StatusCode, data, nil
}

func darwinRunArguments(w *darwinCommandWorker, input string) []string {
	return []string{"audit", "run", "--directory", w.directory,
		"--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json"),
		"--profile", input, "--consent", "metadata-only"}
}

// Never adopt a disk-derived head. Only complete, emitted stdout observations
// below authorize updating w.head or retaining a successor checkpoint file.
func darwinRunObserved(w *darwinCommandWorker, data []byte, outcomes ...string) error {
	checkpoints, err := darwinCommandCheckpoints(data)
	if err != nil || len(checkpoints) != len(outcomes) {
		return errDarwinOrdinary
	}
	events, raw, end, err := w.readSegment()
	if err != nil || len(events) != len(outcomes) {
		return errDarwinOrdinary
	}
	operation := ""
	current := w.start
	for index, outcome := range outcomes {
		_, expected, appendErr := audit.Append(current, events[index])
		if appendErr != nil || checkpoints[index] != expected {
			return errDarwinOrdinary
		}
		current = expected
		if checkpoints[index].Sequence != w.start.Sequence+uint64(index)+1 ||
			events[index].Action != "engine.start" || events[index].Outcome != outcome ||
			len(events[index].OperationID) != 32 {
			return errDarwinOrdinary
		}
		if index == 0 {
			operation = events[index].OperationID
		} else if events[index].OperationID != operation {
			return errDarwinOrdinary
		}
	}
	if len(checkpoints) == 0 || checkpoints[len(checkpoints)-1] != end {
		return errDarwinOrdinary
	}
	if !darwinRunPrivateMetadata(w, data, raw) {
		return errDarwinOrdinary
	}
	w.head = checkpoints[len(checkpoints)-1]
	return nil
}

func darwinRunPrivateMetadata(w *darwinCommandWorker, outputs ...[]byte) bool {
	input, err := darwinCommandReadDefault(w.profilePath)
	if err != nil {
		return false
	}
	p, err := profile.Decode(bytes.NewReader(input))
	if err != nil {
		return false
	}
	key, err := darwinCommandReadDefault(filepath.Join(w.directory, ".actor-key"))
	if err != nil || len(key) < 32 {
		return false
	}
	defer clear(key)
	private := [][]byte{input, []byte(p.ID), []byte(p.Name), []byte(p.Binary), []byte(w.base), []byte(w.profilePath), key, key[len(key)-32:]}
	for _, output := range outputs {
		for _, value := range private {
			if len(value) != 0 && bytes.Contains(output, value) {
				return false
			}
		}
	}
	return true
}

// Exclude only the journal that this explicit operation is expected to append.
// Inputs, key, independently retained checkpoint files and the fixed HKLM pair
// remain in the snapshot. The staged approved engine is protected separately.
func darwinRunPreservedInputs(w *darwinCommandWorker) (map[string][]byte, error) {
	before := w.sources()
	if len(before) == 0 {
		return nil, errDarwinOrdinary
	}
	delete(before, filepath.Join(w.directory, "events.journal"))
	engine, err := darwinCommandRead(w.engine, 128<<20)
	if err != nil || len(engine) == 0 {
		return nil, errDarwinOrdinary
	}
	before[w.engine] = engine
	return before, nil
}

// Test native exclusion directly, including a failed intent observation whose
// disk-derived terminal checkpoint must never be reused as retained authority.
// Opening existing lock-bearing files does not recreate or truncate anything.

func (w *darwinCommandWorker) runApprovedAndRefusals() error {
	child, err := w.newStream("run-approved")
	if err != nil {
		return errDarwinOrdinary
	}
	before, err := darwinRunPreservedInputs(child)
	if err != nil {
		return errDarwinOrdinary
	}
	command := darwinRunArguments(child, child.profilePath)
	observed, notice, err := child.command(command, nil, nil)
	if err != nil || string(notice) != darwinRunLaunchNotice ||
		darwinRunObserved(child, observed, "intent", "accepted", "completed") != nil ||
		!darwinRunPrivateMetadata(child, notice) || !child.preserved(before) ||
		darwinRunReleased(child) != nil {
		return errDarwinOrdinary
	}
	// The retained file still contains genesis. The in-memory head above came
	// from stdout, but is deliberately not retained until after this retry.
	stale := child.sources()
	retry, retryNotice, err := child.command(command, nil, nil)
	if err == nil || len(retry) != 0 || len(retryNotice) != 0 || !child.preserved(stale) ||
		darwinRunReleased(child) != nil {
		return errDarwinOrdinary
	}
	if child.writeHead() != nil || child.exportVerify(3) != nil {
		return errDarwinOrdinary
	}
	input, err := darwinCommandReadDefault(child.profilePath)
	if err != nil {
		return errDarwinOrdinary
	}
	unapproved, err := profile.Decode(bytes.NewReader(input))
	if err != nil {
		return errDarwinOrdinary
	}
	unapproved.Routing.IncludeDomains = []string{"unapproved-native-fixture.invalid"}
	unapprovedBytes, err := json.Marshal(unapproved)
	if err != nil {
		return errDarwinOrdinary
	}
	unapprovedPath := filepath.Join(child.base, "unapproved-run-profile.json")
	if child.ownFile(unapprovedPath, unapprovedBytes) != nil {
		return errDarwinOrdinary
	}
	preserved := child.sources()
	preserved[unapprovedPath] = bytes.Clone(unapprovedBytes)
	preserved[child.engine] = bytes.Clone(before[child.engine])
	refused, refusedNotice, err := child.command(darwinRunArguments(child, unapprovedPath), nil, nil)
	if !errors.Is(err, errAuditRunPreview) || len(refused) != 0 || len(refusedNotice) != 0 ||
		!child.preserved(preserved) || darwinRunReleased(child) != nil {
		return errDarwinOrdinary
	}
	return nil
}

func darwinRunClosedOutput() (*os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, errDarwinOrdinary
	}
	if reader.Close() != nil {
		_ = writer.Close()
		return nil, errDarwinOrdinary
	}
	return writer, nil
}

func darwinRunOutputFailure(w *darwinCommandWorker, intent bool) (failure error) {
	label := "run-notice-output-failure"
	if intent {
		label = "run-intent-output-failure"
	}
	child, err := w.newStream(label)
	if err != nil {
		return errDarwinOrdinary
	}
	before, err := darwinRunPreservedInputs(child)
	if err != nil {
		return errDarwinOrdinary
	}
	broken, err := darwinRunClosedOutput()
	if err != nil {
		return errDarwinOrdinary
	}
	defer func() {
		if broken.Close() != nil {
			failure = errDarwinOrdinary
		}
	}()
	var observed, notice []byte
	if intent {
		observed, notice, err = child.command(darwinRunArguments(child, child.profilePath), broken, nil)
	} else {
		observed, notice, err = child.command(darwinRunArguments(child, child.profilePath), nil, broken)
	}
	if intent {
		if !errors.Is(err, audit.ErrRecorderUnavailable) || len(observed) != 0 || len(notice) != 0 {
			return errDarwinOrdinary
		}
		events, raw, _, segmentErr := child.readSegment()
		if segmentErr != nil || len(events) != 2 || events[0].Action != "engine.start" ||
			events[1].Action != "engine.start" || events[0].Outcome != "intent" ||
			events[1].Outcome != "refused" || len(events[0].OperationID) != 32 ||
			events[0].OperationID != events[1].OperationID || !darwinRunPrivateMetadata(child, raw) {
			return errDarwinOrdinary
		}
		// No stdout successor was observed: leave child.head at genesis and
		// do not open another audit writer or export with a disk-derived head.
	} else {
		if !errors.Is(err, audit.ErrRecordedUncertain) ||
			darwinRunObserved(child, observed, "intent", "accepted", "completed") != nil ||
			len(notice) != 0 || child.writeHead() != nil || child.exportVerify(3) != nil {
			return errDarwinOrdinary
		}
		// writeHead intentionally changed only the separately retained head.
		delete(before, filepath.Join(child.base, "head.json"))
	}
	if !child.preserved(before) || darwinRunReleased(child) != nil {
		return errDarwinOrdinary
	}
	return nil
}

func (w *darwinCommandWorker) seedCapacity() error {
	if w.start.Sequence != 0 || w.head != w.start {
		return errDarwinOrdinary
	}
	genesis, err := audit.EncodeCheckpoint(w.start)
	if err != nil {
		return errDarwinOrdinary
	}
	current, err := darwinCommandReadDefault(filepath.Join(w.directory, "events.journal"))
	if err != nil || !bytes.Equal(current, genesis) {
		return errDarwinOrdinary
	}
	full := bytes.Clone(genesis)
	head := w.start
	for index := uint64(0); index < audit.MaxSegmentRecords-1; index++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return errDarwinOrdinary
		}
		line, next, err := audit.Append(head, audit.Event{
			OccurredAt: time.Now().UTC(), OperationID: hex.EncodeToString(random[:]),
			Action: "profile.write", Outcome: "completed",
		})
		clear(random[:])
		if err != nil || len(full)+len(line) > audit.MaxJournalBytes {
			return errDarwinOrdinary
		}
		full = append(full, line...)
		head = next
	}
	verified, err := audit.VerifySegment(w.ctx, bytes.NewReader(full[len(genesis):]), w.start, head)
	if err != nil || uint64(verified.Records) != audit.MaxSegmentRecords-1 ||
		w.put(filepath.Join(w.directory, "events.journal"), full) != nil {
		return errDarwinOrdinary
	}
	w.head = head
	if w.writeHead() != nil {
		return errDarwinOrdinary
	}
	events, raw, observed, err := w.readSegment()
	if err != nil || uint64(len(events)) != audit.MaxSegmentRecords-1 ||
		observed != head || !bytes.Equal(raw, full) {
		return errDarwinOrdinary
	}
	return nil
}

func darwinAliasArguments(w *darwinCommandWorker, action string) []string {
	switch action {
	case "import":
		return w.importArgs()
	case "export-recorded":
		return w.exportArgs(true)
	case "ui":
		return []string{"audit", "ui", "--directory", w.directory,
			"--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json")}
	case "run":
		return []string{"audit", "run", "--directory", w.directory,
			"--from", filepath.Join(w.base, "genesis.json"), "--to", filepath.Join(w.base, "head.json"),
			"--profile", w.profilePath, "--consent", "metadata-only"}
	}
	return nil
}

func (w *darwinCommandWorker) capacityRefusal() error {
	child, err := w.newStream("capacity")
	if err != nil || child.seedCapacity() != nil {
		return errDarwinOrdinary
	}
	before := child.sources()
	if before == nil {
		return errDarwinOrdinary
	}
	for _, action := range []string{"import", "export-recorded", "run"} {
		out, notice, commandErr := child.command(darwinAliasArguments(child, action), nil, nil)
		expected := audit.ErrRecorderUnavailable
		if action == "import" {
			expected = errAuditImportAdmission
		}
		if !errors.Is(commandErr, expected) || len(out) != 0 || len(notice) != 0 ||
			!child.preserved(before) || child.recordProducts() != nil {
			return errDarwinOrdinary
		}
		entries, err := os.ReadDir(filepath.Join(child.state, "profiles"))
		if err != nil || len(entries) != 0 {
			return errDarwinOrdinary
		}
	}
	events, _, head, err := child.readSegment()
	if err != nil || uint64(len(events)) != audit.MaxSegmentRecords-1 || head != child.head {
		return errDarwinOrdinary
	}
	// Exercise the real private launcher/HTTP mutation path at the same
	// reservation boundary; the main desktop helper owns signal/HTTP cleanup.
	return w.desktop(true)
}

func (w *darwinCommandWorker) desktop(full bool) (failure error) {
	label := "desktop"
	if full {
		label = "full-desktop"
	}
	s, err := w.newStream(label)
	if err != nil {
		return err
	}
	if full && s.seedCapacity() != nil {
		return errDarwinOrdinary
	}
	previousBrowser, hadBrowser := os.LookupEnv("ACCESSWEAVER_NO_BROWSER")
	if os.Setenv("ACCESSWEAVER_NO_BROWSER", "1") != nil {
		return errDarwinOrdinary
	}
	defer func() {
		var restoreErr error
		if hadBrowser {
			restoreErr = os.Setenv("ACCESSWEAVER_NO_BROWSER", previousBrowser)
		} else {
			restoreErr = os.Unsetenv("ACCESSWEAVER_NO_BROWSER")
		}
		if restoreErr != nil {
			failure = errDarwinOrdinary
		}
	}()
	reader, writer, err := os.Pipe()
	if err != nil {
		return errDarwinOrdinary
	}
	type desktopResult struct {
		output []byte
		err    error
	}
	done := make(chan desktopResult, 1)
	var uiOutput []byte
	go func() {
		output, _, err := s.command([]string{"audit", "ui", "--directory", s.directory, "--from", filepath.Join(s.base, "genesis.json"), "--to", filepath.Join(s.base, "head.json")}, nil, writer)
		if writer.Close() != nil {
			darwinCommandCloseFailure = true
			err = errDarwinOrdinary
		}
		done <- desktopResult{output, err}
	}()
	startup := make(chan string, 1)
	scanned := make(chan struct{})
	defer func() {
		if err := reader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			failure = errDarwinOrdinary
		}
		<-scanned
	}()
	go func() {
		defer close(scanned)
		scan := bufio.NewScanner(io.LimitReader(reader, 16385))
		scan.Buffer(make([]byte, 1024), 16384)
		for scan.Scan() {
			line := scan.Text()
			const prefix = "Open this private launch file in your browser: "
			if strings.HasPrefix(line, prefix) {
				startup <- strings.TrimPrefix(line, prefix)
				return
			}
		}
		startup <- ""
	}()
	var launch string
	select {
	case launch = <-startup:
	case <-time.After(15 * time.Second):
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		select {
		case result := <-done:
			clear(result.output)
		case <-time.After(15 * time.Second):
			// The shared active guard forbids workspace unlink while the
			// actual UI command has not confirmed its owned completion.
		}
		return errDarwinOrdinary
	}
	stop := func() error {
		select {
		case result := <-done:
			uiOutput = result.output
			return result.err
		default:
		}
		if syscall.Kill(os.Getpid(), syscall.SIGTERM) != nil {
			return errDarwinOrdinary
		}
		select {
		case result := <-done:
			uiOutput = result.output
			return result.err
		case <-time.After(15 * time.Second):
			return errDarwinOrdinary
		}
	}
	if launch == "" {
		_ = stop()
		return errDarwinOrdinary
	}
	parsed, err := url.Parse(launch)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" {
		_ = stop()
		return errDarwinOrdinary
	}
	path := filepath.FromSlash(parsed.Path)
	cache, err := os.UserCacheDir()
	if err != nil || filepath.Dir(filepath.Dir(path)) != cache || !strings.HasPrefix(filepath.Base(filepath.Dir(path)), "accessweaver-ui-") || filepath.Base(path) != "start.html" {
		_ = stop()
		return errDarwinOrdinary
	}

	if _, err := darwinOrdinaryPrivate(path, false, w.uid); err != nil {
		_ = stop()
		return errDarwinOrdinary
	}
	if _, err := darwinOrdinaryPrivate(filepath.Dir(path), true, w.uid); err != nil {
		_ = stop()
		return errDarwinOrdinary
	}
	page, err := darwinCommandReadDefault(path)
	if err != nil || len(page) > 8192 {
		_ = stop()
		return errDarwinOrdinary
	}
	text := html.UnescapeString(string(page))
	start := strings.Index(text, "http://127.0.0.1:")
	if start < 0 {
		_ = stop()
		return errDarwinOrdinary
	}
	tail := text[start:]
	end := strings.IndexAny(tail, "\"<> \r\n")
	if end < 0 {
		_ = stop()
		return errDarwinOrdinary
	}
	target, err := url.Parse(tail[:end])
	if err != nil || target.Scheme != "http" || target.Hostname() != "127.0.0.1" || target.Port() == "" || !strings.HasPrefix(target.Fragment, "accessweaver-session=") {
		_ = stop()
		return errDarwinOrdinary
	}
	token := strings.TrimPrefix(target.Fragment, "accessweaver-session=")
	target.Fragment = ""
	if len(token) != 43 {
		_ = stop()
		return errDarwinOrdinary
	}
	address := strings.TrimSuffix(target.String(), "/")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, route, credential string, input any, expected int) ([]byte, error) {
		status, data, err := darwinHTTP(client, method, address+route, credential, input)
		if err != nil || status != expected {
			clear(data)
			return nil, errDarwinOrdinary
		}
		return data, nil
	}
	if _, err := call("GET", "/api/bootstrap", token, nil, 200); err != nil {
		_ = stop()
		return errDarwinOrdinary
	}
	if _, err := call("PUT", "/api/v1/profiles/"+s.p.ID, "", s.p, 403); err != nil {
		_ = stop()
		return errDarwinOrdinary
	}
	if full {
		if _, err := call("PUT", "/api/v1/profiles/"+s.p.ID, token, s.p, 503); err != nil {
			_ = stop()
			return errDarwinOrdinary
		}
	} else {
		data, err := call("PUT", "/api/v1/profiles/"+s.p.ID, token, s.p, 200)
		var saved profile.Profile
		if err != nil || json.Unmarshal(data, &saved) != nil || s.adoptProfile(saved) != nil {
			_ = stop()
			return errDarwinOrdinary
		}
		if _, err := call("PUT", "/api/v1/profiles/"+s.p.ID, token, s.p, 409); err != nil {
			_ = stop()
			return errDarwinOrdinary
		}
		saved.Name = "PRIVATE_UPDATED_ORDINARY_PROFILE"
		data, err = call("PUT", "/api/v1/profiles/"+s.p.ID, token, saved, 200)
		if err != nil || json.Unmarshal(data, &saved) != nil || s.adoptProfile(saved) != nil {
			_ = stop()
			return errDarwinOrdinary
		}
		if _, err := call("DELETE", "/api/v1/profiles/"+s.p.ID, token, map[string]any{"expectedUpdatedAt": saved.UpdatedAt}, 200); err != nil {
			_ = stop()
			return errDarwinOrdinary
		}
		if s.forget(filepath.Join(s.state, "profiles", saved.ID+".json")) != nil {
			_ = stop()
			return errDarwinOrdinary
		}
	}
	for _, route := range []string{"/api/v1/start", "/api/v1/stop", "/api/v1/diagnose", "/api/v1/system/start", "/api/v1/support"} {
		method := "POST"
		if route == "/api/v1/support" {
			method = "GET"
		}
		if _, err := call(method, route, token, map[string]any{}, 403); err != nil {
			_ = stop()
			return errDarwinOrdinary
		}
	}
	if stop() != nil || s.recordProducts() != nil {
		return errDarwinOrdinary
	}
	if _, err := fileidentity.FromPath(path, false); !errors.Is(err, os.ErrNotExist) {
		return errDarwinOrdinary
	}
	if _, err := fileidentity.FromPath(filepath.Dir(path), false); !errors.Is(err, os.ErrNotExist) {
		return errDarwinOrdinary
	}
	events, _, head, err := s.readSegment()
	expected := 8
	if full {
		expected = 4095
	}
	if err != nil || len(events) != expected {
		return errDarwinOrdinary
	}
	if full {
		if len(uiOutput) != 0 || head != s.head {
			return errDarwinOrdinary
		}
	} else {
		observed, err := darwinCommandCheckpoints(uiOutput)
		if err != nil || len(observed) != 8 || observed[len(observed)-1] != head {
			return errDarwinOrdinary
		}
		current := s.start
		actions := []string{"profile.write", "profile.write", "profile.write", "profile.write", "profile.write", "profile.write", "profile.delete", "profile.delete"}
		outcomes := []string{"intent", "completed", "intent", "refused", "intent", "completed", "intent", "completed"}
		for i, checkpoint := range observed {
			_, expected, appendErr := audit.Append(current, events[i])
			if appendErr != nil || checkpoint != expected || events[i].Action != actions[i] || events[i].Outcome != outcomes[i] {
				return errDarwinOrdinary
			}
			if i%2 == 1 && events[i].OperationID != events[i-1].OperationID {
				return errDarwinOrdinary
			}
			current = expected
		}
		s.head = observed[len(observed)-1]
	}
	if !full && s.exportVerify(8) != nil {
		return errDarwinOrdinary
	}
	reopened, err := audit.OpenLocalJournal(s.ctx, s.directory, s.start, s.head)
	if err != nil {
		return errDarwinOrdinary
	}
	if reopened.Close() != nil {
		return errDarwinOrdinary
	}
	lock, err := filelock.TryAcquire(filepath.Join(s.state, ".controller.lock"))
	if err != nil || lock.Close() != nil {
		return errDarwinOrdinary
	}
	return nil
}

func (w *darwinCommandWorker) requiredAdmission() error {
	s, err := w.newStream("required")
	if err != nil {
		return err
	}
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid || status.Revision != 1 {
		return errDarwinOrdinary
	}
	source, err := managed.ExportInstallation()
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(source)
	var installation managed.Installation
	if json.Unmarshal(source, &installation) != nil {
		return errDarwinOrdinary
	}
	public, err := managed.PublicKey(installation.PublicKey)
	if err != nil {
		return errDarwinOrdinary
	}
	envelope, err := json.Marshal(installation.Envelope)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(envelope)
	verified, err := managed.Verify(envelope, public, time.Now(), 0)
	if err != nil || verified.Policy.Revision != 1 || !verified.Policy.AllowProfileChanges || !verified.Policy.RequireProfileAudit {
		return errDarwinOrdinary
	}
	before := s.sources()
	out, notice, err := s.command([]string{"import", s.profilePath}, nil, nil)
	if !errors.Is(err, managed.ErrDenied) || len(out) != 0 || len(notice) != 0 || !s.preserved(before) {
		return errDarwinOrdinary
	}
	store, err := profile.NewStore(s.state)
	if err != nil {
		return errDarwinOrdinary
	}
	for _, operation := range []func() error{
		func() error { return store.Save(s.p) },
		func() error { return store.SaveIfUnchangedContext(s.ctx, s.p) },
		func() error { return store.Delete(s.p.ID) },
		func() error { return store.DeleteIfUnchangedContext(s.ctx, s.p.ID, time.Now()) },
		func() error {
			return profile.RestoreSnapshot(s.ctx, filepath.Join(s.base, "must-remain-absent"), []profile.Profile{s.p}, false, managed.NewGuard(nil))
		},
	} {
		if !errors.Is(operation(), managed.ErrDenied) {
			return errDarwinOrdinary
		}
	}
	server, err := api.New(store, engine.NewManager(s.state), nil)
	if err != nil {
		return errDarwinOrdinary
	}
	body, err := json.Marshal(s.p)
	if err != nil {
		return errDarwinOrdinary
	}
	request := httptest.NewRequest(http.MethodPut, "http://127.0.0.1/api/v1/profiles/"+s.p.ID, bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AccessWeaver-Token", server.Token)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		return errDarwinOrdinary
	}
	entries, err := os.ReadDir(filepath.Join(s.state, "profiles"))
	if err != nil || len(entries) != 0 || !s.preserved(before) || s.recordProducts() != nil {
		return errDarwinOrdinary
	}
	if _, err := os.Lstat(filepath.Join(s.base, "must-remain-absent")); !errors.Is(err, os.ErrNotExist) {
		return errDarwinOrdinary
	}
	for _, path := range []string{darwinCommandPolicy, darwinCommandAcceptance, w.engine, w.manifest().holdProfile.Binary} {
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			if file.Close() != nil {
				darwinCommandCloseFailure = true
			}
			return errDarwinOrdinary
		}
		if !errors.Is(err, os.ErrPermission) {
			return errDarwinOrdinary
		}
	}
	if _, err := managed.Update([]byte("{}")); !errors.Is(err, managed.ErrDenied) {
		return errDarwinOrdinary
	}
	return nil
}
func (w *darwinCommandWorker) currentExport() error {
	s, err := w.newStream("current-export")
	if err != nil {
		return err
	}
	output, notice, err := s.command(s.exportArgs(true), nil, nil)
	if err != nil || len(output) != 0 {
		return errDarwinOrdinary
	}
	observations, err := darwinCommandCheckpoints(notice)
	if err != nil || len(observations) != 2 || observations[0].Sequence != 1 || observations[1].Sequence != 2 {
		return errDarwinOrdinary
	}
	s.head = observations[1]
	events, _, head, err := s.readSegment()
	if err != nil || head != s.head || len(events) != 2 || events[0].Action != "audit.export" || events[1].Action != "audit.export" || events[0].Outcome != "intent" || events[1].Outcome != "completed" || events[0].OperationID != events[1].OperationID {
		return errDarwinOrdinary
	}
	if s.exportVerify(2) != nil {
		return errDarwinOrdinary
	}
	before := s.sources()
	args := s.exportArgs(true)
	args[len(args)-1] = "rejected-consent"
	out, notice, err := s.command(args, nil, nil)
	if !errors.Is(err, errAuditExportConsent) || len(out) != 0 || len(notice) != 0 || !s.preserved(before) {
		return errDarwinOrdinary
	}
	keyPath := filepath.Join(s.directory, ".actor-key")
	key, err := darwinCommandReadDefault(keyPath)
	if err != nil || len(key) < 32 {
		return errDarwinOrdinary
	}
	defer clear(key)
	changed := bytes.Clone(key)
	defer clear(changed)
	changed[len(changed)-1] ^= 1
	if s.put(keyPath, changed) != nil {
		return errDarwinOrdinary
	}
	before = s.sources()
	out, notice, err = s.command(s.exportArgs(true), nil, nil)
	if err == nil || len(out) != 0 || len(notice) != 0 || !s.preserved(before) || s.exportVerify(2) != nil {
		return errDarwinOrdinary
	}
	if s.put(keyPath, key) != nil || s.remove(keyPath) != nil {
		return errDarwinOrdinary
	}
	journalBefore, err := darwinCommandReadDefault(filepath.Join(s.directory, "events.journal"))
	if err != nil {
		return errDarwinOrdinary
	}
	out, notice, err = s.command(s.exportArgs(true), nil, nil)
	journalAfter, readErr := darwinCommandReadDefault(filepath.Join(s.directory, "events.journal"))
	if err == nil || readErr != nil || len(out) != 0 || len(notice) != 0 || !bytes.Equal(journalBefore, journalAfter) || s.exportVerify(2) != nil {
		return errDarwinOrdinary
	}
	if _, err := os.Lstat(keyPath); !errors.Is(err, os.ErrNotExist) {
		return errDarwinOrdinary
	}
	return nil
}
func darwinRunReleased(w *darwinCommandWorker) error {
	entries, err := os.ReadDir(filepath.Join(w.state, "profiles"))
	if err != nil || len(entries) != 0 || w.recordProducts() != nil {
		return errDarwinOrdinary
	}
	for _, path := range []string{filepath.Join(w.state, ".controller.lock"), filepath.Join(w.directory, "events.journal")} {
		if w.record(path) != nil {
			return errDarwinOrdinary
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return errDarwinOrdinary
		}
		raw, rawErr := file.SyscallConn()
		var lockErr error
		if rawErr == nil {
			rawErr = raw.Control(func(fd uintptr) { lockErr = unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB) })
		}
		closeErr := file.Close()
		if rawErr != nil || lockErr != nil || closeErr != nil || w.record(path) != nil {
			return errDarwinOrdinary
		}
	}
	return nil
}
func darwinAliasInvoke(w *darwinCommandWorker, action string, stdout, stderr *os.File) ([]byte, []byte, error, bool) {
	ctx, cancel := context.WithCancel(w.ctx)
	defer cancel()
	done := make(chan struct{})
	var fired atomic.Bool
	go func() {
		defer close(done)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			fired.Store(true)
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		}
	}()
	out, notice, err := w.command(darwinAliasArguments(w, action), stdout, stderr)
	cancel()
	<-done
	return out, notice, err, fired.Load()
}
func darwinAliasExpected(action string) error {
	switch action {
	case "import":
		return errAuditImportAdmission
	case "run":
		return errAuditRunOutput
	case "export-recorded":
		return audit.ErrExportDestination
	default:
		return errAuditOutputAlias
	}
}
func darwinAliasAttempt(w *darwinCommandWorker, action, source, variant string, role int) error {
	before := w.sources()
	if before == nil {
		return errDarwinOrdinary
	}
	extra, err := darwinCommandReadSource(w, source)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(extra)
	sourceState, err := fileidentity.FromPath(source, false)
	if err != nil || sourceState.Kind != fileidentity.Regular {
		return errDarwinOrdinary
	}
	before[source] = bytes.Clone(extra)
	path := source
	created := ""
	var createdID fileidentity.ID
	removeAlias := func() error {
		if created == "" {
			return nil
		}
		current, err := fileidentity.FromPath(created, false)
		if err != nil || current.ID != createdID || current.Kind != fileidentity.Regular {
			return errDarwinOrdinary
		}
		if os.Remove(created) != nil {
			return errDarwinOrdinary
		}
		created = ""
		return nil
	}
	switch variant {
	case "hardlink":
		w.manifest().counter++
		created = filepath.Join(w.base, "output-hardlink-"+strconv.FormatUint(uint64(w.manifest().counter), 10))
		if os.Link(source, created) != nil {
			return errDarwinOrdinary
		}
		path = created
		state, err := fileidentity.FromPath(created, false)
		if err != nil || state.ID != sourceState.ID {
			return errDarwinOrdinary
		}
		createdID = state.ID
	case "case":
		path = filepath.Join(filepath.Dir(source), strings.ToUpper(filepath.Base(source)))
		changed, err := fileidentity.FromPath(path, false)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || changed.ID != sourceState.ID {
			return errDarwinOrdinary
		}
	case "direct":
	default:
		return errDarwinOrdinary
	}
	file, err := os.Open(path)
	if err != nil {
		_ = removeAlias()
		return errDarwinOrdinary
	}
	id, idErr := fileidentity.FromFile(file)
	var out, notice []byte
	var commandErr error
	var watchdog bool
	if role == 0 {
		out, notice, commandErr, watchdog = darwinAliasInvoke(w, action, file, nil)
	} else {
		out, notice, commandErr, watchdog = darwinAliasInvoke(w, action, nil, file)
	}
	closeErr := file.Close()
	if closeErr != nil {
		darwinCommandCloseFailure = true
	}
	removeErr := removeAlias()
	afterState, stateErr := fileidentity.FromPath(source, false)
	if watchdog || idErr != nil || id.ID != sourceState.ID || closeErr != nil || removeErr != nil || stateErr != nil || afterState.ID != sourceState.ID ||
		!errors.Is(commandErr, darwinAliasExpected(action)) || len(out) != 0 || len(notice) != 0 || !w.preserved(before) || w.recordProducts() != nil {
		return errDarwinOrdinary
	}
	return nil
}

func (w *darwinCommandWorker) aliasAdmission() error {
	child, err := w.newStream("aliases")
	if err != nil {
		return errDarwinOrdinary
	}
	common := []string{filepath.Join(child.base, "genesis.json"), filepath.Join(child.base, "head.json"), filepath.Join(child.directory, ".actor-key"), filepath.Join(child.directory, "events.journal")}
	for _, action := range []string{"import", "ui", "export-recorded", "run"} {
		sources := append([]string{}, common...)
		roles := 2
		if action == "import" {
			roles = 1
		}
		if action == "import" || action == "run" {
			sources = append(sources, child.profilePath)
		}
		for _, source := range sources {
			for _, variant := range []string{"direct", "hardlink", "case"} {
				for role := 0; role < roles; role++ {
					if child.ctx.Err() != nil || darwinAliasAttempt(child, action, source, variant, role) != nil {
						return errDarwinOrdinary
					}
				}
			}
		}
	}
	for _, source := range []string{child.engine, darwinCommandPolicy, darwinCommandAcceptance} {
		for role := 0; role < 2; role++ {
			if darwinAliasAttempt(child, "run", source, "direct", role) != nil {
				return errDarwinOrdinary
			}
		}
	}
	for _, name := range []string{".controller.lock", ".profiles.lock"} {
		path := filepath.Join(child.state, name)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if child.ownFile(path, nil) != nil {
				return errDarwinOrdinary
			}
		} else if err != nil || child.record(path) != nil {
			return errDarwinOrdinary
		}
		for _, variant := range []string{"direct", "hardlink", "case"} {
			for role := 0; role < 2; role++ {
				if darwinAliasAttempt(child, "run", path, variant, role) != nil {
					return errDarwinOrdinary
				}
			}
		}
	}
	// A private root-owned coordination file grants no ordinary read descriptor.
	// Its permission refusal is separate from actual forwarded alias acceptance.
	coordination, coordinationErr := os.Open(darwinCommandCoordination)
	if coordinationErr == nil {
		if coordination.Close() != nil {
			return errDarwinOrdinary
		}
		for role := 0; role < 2; role++ {
			if darwinAliasAttempt(child, "run", darwinCommandCoordination, "direct", role) != nil {
				return errDarwinOrdinary
			}
		}
	} else if !errors.Is(coordinationErr, os.ErrPermission) {
		return errDarwinOrdinary
	}
	// Config is an explicit first-pass protected input even though this changed
	// fixture profile is not a signed launch rule. No engine may be launched.
	configPath := filepath.Join(child.base, "unapproved-config.json")
	if child.ownFile(configPath, []byte("{}")) != nil {
		return errDarwinOrdinary
	}
	original, err := darwinCommandReadDefault(child.profilePath)
	if err != nil {
		return errDarwinOrdinary
	}
	configured := child.p
	configured.ConfigPath = configPath
	configuredBytes, err := json.Marshal(configured)
	if err != nil || child.put(child.profilePath, configuredBytes) != nil {
		return errDarwinOrdinary
	}
	for role := 0; role < 2; role++ {
		if darwinAliasAttempt(child, "run", configPath, "direct", role) != nil {
			return errDarwinOrdinary
		}
	}
	if child.put(child.profilePath, original) != nil {
		return errDarwinOrdinary
	}
	// Pairwise forwarding targets are independently rejected before any bytes.
	for _, action := range []string{"ui", "export-recorded", "run"} {
		root := child.manifest()
		root.counter++
		path := filepath.Join(child.base, "pairwise-"+strconv.FormatUint(uint64(root.counter), 10))
		if child.ownFile(path, nil) != nil {
			return errDarwinOrdinary
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return errDarwinOrdinary
		}
		before := child.sources()
		out, notice, commandErr, watchdog := darwinAliasInvoke(child, action, file, file)
		closeErr := file.Close()
		if closeErr != nil {
			darwinCommandCloseFailure = true
		}
		content, readErr := darwinCommandReadDefault(path)
		if watchdog || closeErr != nil || readErr != nil || len(content) != 0 || len(out) != 0 || len(notice) != 0 || !errors.Is(commandErr, darwinAliasExpected(action)) || !child.preserved(before) || child.recordProducts() != nil {
			return errDarwinOrdinary
		}
	}
	return nil
}
func runDarwinCommandCases(request darwinOrdinaryRequest) (executed, passed uint64) {
	if os.Getuid() != darwinOrdinaryUID || os.Geteuid() != darwinOrdinaryUID || os.Getgid() != darwinOrdinaryUID || os.Getegid() != darwinOrdinaryUID ||
		request.Profile.Binary != request.Engine || request.HoldProfile.Binary != request.HoldEngine || len(request.Profile.Args) != 0 || len(request.HoldProfile.Args) != 0 {
		return 0, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	root := &darwinCommandWorker{base: request.Workspace, state: request.State, home: request.Home, uid: darwinOrdinaryUID, engine: request.Engine, p: request.Profile, holdProfile: request.HoldProfile, ctx: ctx, active: new(atomic.Int32)}
	fd, err := unix.Open(request.Home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0
	}
	root.parent = os.NewFile(uintptr(fd), "ordinary-command-home")
	if root.mkdirPrivate(root.base) != nil {
		executed |= 1 << 9
		if root.close() == nil {
			passed |= 1 << 9
		}
		return executed, passed
	}
	operations := []func() error{root.requiredAdmission, root.importRoundTrip, func() error { return root.desktop(false) }, root.historicalRoundTrip, root.currentExport, root.aliasAdmission, root.capacityRefusal, root.runApprovedAndRefusals, root.runFailuresAndCancellation}
	for index, operation := range operations {
		if ctx.Err() != nil {
			root.preserve = true
			break
		}
		executed |= uint64(1) << index
		if operation() != nil {
			root.preserve = true
			break
		}
		passed |= uint64(1) << index
		if root.sweep() != nil {
			root.preserve = true
			break
		}
	}
	executed |= 1 << 9
	if root.close() == nil {
		passed |= 1 << 9
	}
	return executed, passed
}

const darwinRunLaunchNotice = "Process launched. This does not guarantee functional routing or connection.\n"

func darwinRunUseHold(child *darwinCommandWorker) error {
	held := child.manifest().holdProfile
	if held.Binary == "" || len(held.Args) != 0 {
		return errDarwinOrdinary
	}
	child.p, child.engine = held, held.Binary
	data, err := json.Marshal(held)
	if err != nil {
		return errDarwinOrdinary
	}
	defer clear(data)
	return child.put(child.profilePath, data)
}
func darwinRunObservationPrefix(w *darwinCommandWorker, file *os.File) bool {
	data, err := io.ReadAll(io.NewSectionReader(file, 0, 3*audit.MaxCheckpointBytes+1))
	if err != nil || len(data) > 3*audit.MaxCheckpointBytes {
		return false
	}
	observed, err := darwinCommandCheckpoints(data)
	if err != nil || len(observed) != 2 {
		return false
	}
	events, _, _, err := w.readSegment()
	if err != nil || len(events) != 2 {
		return false
	}
	current := w.start
	for index, outcome := range []string{"intent", "accepted"} {
		_, expected, appendErr := audit.Append(current, events[index])
		if appendErr != nil || observed[index] != expected || events[index].Action != "engine.start" || events[index].Outcome != outcome {
			return false
		}
		if index == 1 && events[index].OperationID != events[0].OperationID {
			return false
		}
		current = expected
	}
	return true
}
func darwinRunCancellation(w *darwinCommandWorker) (failure error) {
	child, err := w.newStream("run-cancellation")
	if err != nil || darwinRunUseHold(child) != nil {
		return errDarwinOrdinary
	}
	before, err := darwinRunPreservedInputs(child)
	if err != nil {
		return errDarwinOrdinary
	}
	observations, err := child.privateCapture()
	if err != nil {
		return errDarwinOrdinary
	}
	defer func() {
		if observations.Close() != nil {
			failure = errDarwinOrdinary
		}
	}()
	reader, writer, err := os.Pipe()
	if err != nil {
		return errDarwinOrdinary
	}
	signalCtx, cancelSignal := context.WithTimeout(child.ctx, 10*time.Second)
	defer cancelSignal()
	signaled := make(chan bool, 1)
	darwinOrdinaryDrainReady()
	go func() {
		notice := make([]byte, len(darwinRunLaunchNotice))
		_, readErr := io.ReadFull(reader, notice)
		ready := readErr == nil && string(notice) == darwinRunLaunchNotice && darwinOrdinaryWaitHoldReady(signalCtx)
		ready = ready && darwinRunObservationPrefix(child, observations)
		if ready {
			ready = syscall.Kill(os.Getpid(), syscall.SIGTERM) == nil
		}
		if reader.Close() != nil {
			ready = false
		}
		signaled <- ready
	}()
	_, _, commandErr := child.command(darwinRunArguments(child, child.profilePath), observations, writer)
	closeErr := writer.Close()
	cancelSignal()
	// This joins the owned reader, including any native observation I/O.
	// A context is not permission to abandon an in-flight native operation.
	confirmed := <-signaled
	output, readErr := io.ReadAll(io.NewSectionReader(observations, 0, audit.MaxJournalBytes+1))
	if closeErr != nil || readErr != nil || len(output) > audit.MaxJournalBytes || !confirmed || commandErr != nil ||
		darwinRunObserved(child, output, "intent", "accepted", "completed") != nil || !child.preserved(before) || darwinRunReleased(child) != nil {
		return errDarwinOrdinary
	}
	if child.writeHead() != nil || child.exportVerify(3) != nil {
		return errDarwinOrdinary
	}
	return nil
}
func darwinRunFilledNotice() (*os.File, *os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, errDarwinOrdinary
	}
	raw, err := writer.SyscallConn()
	full := false
	var fillErr error
	if err == nil {
		err = raw.Control(func(fd uintptr) {
			flags, nativeErr := unix.FcntlInt(fd, unix.F_GETFL, 0)
			if nativeErr != nil || flags&unix.O_NONBLOCK == 0 {
				fillErr = errDarwinOrdinary
				return
			}
			padding := make([]byte, 4096)
			chunk := len(padding)
			for total := 0; total < 1<<20; {
				size := chunk
				if remaining := 1<<20 - total; size > remaining {
					size = remaining
				}
				n, writeErr := unix.Write(int(fd), padding[:size])
				if errors.Is(writeErr, unix.EAGAIN) || errors.Is(writeErr, unix.EWOULDBLOCK) {
					if size != 1 {
						// A rejected atomic chunk can leave space for the
						// smaller notice. Fill every residual byte first.
						chunk = 1
						continue
					}
					full = true
					return
				}
				if writeErr != nil || n <= 0 {
					fillErr = errDarwinOrdinary
					return
				}
				total += n
			}
		})
	}
	if err != nil || fillErr != nil || !full {
		_ = reader.Close()
		_ = writer.Close()
		return nil, nil, errDarwinOrdinary
	}
	return reader, writer, nil
}
func darwinRunNoticeOutputFailure(w *darwinCommandWorker) (failure error) {
	child, err := w.newStream("run-notice-output-failure")
	if err != nil || darwinRunUseHold(child) != nil {
		return errDarwinOrdinary
	}
	before, err := darwinRunPreservedInputs(child)
	if err != nil {
		return errDarwinOrdinary
	}
	reader, writer, err := darwinRunFilledNotice()
	if err != nil {
		return errDarwinOrdinary
	}
	waitCtx, cancelWait := context.WithTimeout(child.ctx, 10*time.Second)
	defer cancelWait()
	readyResult := make(chan bool, 1)
	darwinOrdinaryDrainReady()
	go func() {
		ready := darwinOrdinaryWaitHoldReady(waitCtx)
		// Only a test-owned full pipe delays the actual notice write until
		// the held engine has installed its real termination handler.
		if reader.Close() != nil {
			ready = false
		}
		readyResult <- ready
	}()
	output, notice, commandErr := child.command(darwinRunArguments(child, child.profilePath), nil, writer)
	closeErr := writer.Close()
	cancelWait()
	ready := <-readyResult
	if !ready || closeErr != nil || !errors.Is(commandErr, audit.ErrRecordedUncertain) || len(notice) != 0 ||
		darwinRunObserved(child, output, "intent", "accepted", "completed") != nil || !child.preserved(before) || darwinRunReleased(child) != nil {
		return errDarwinOrdinary
	}
	if child.writeHead() != nil || child.exportVerify(3) != nil {
		return errDarwinOrdinary
	}
	return nil
}
func (w *darwinCommandWorker) runFailuresAndCancellation() error {
	if darwinRunOutputFailure(w, true) != nil || darwinRunNoticeOutputFailure(w) != nil || darwinRunCancellation(w) != nil {
		return errDarwinOrdinary
	}
	return nil
}
