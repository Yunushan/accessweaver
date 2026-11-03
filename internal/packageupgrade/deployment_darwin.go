//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

const deploymentParent = "/Library/Application Support"
const deploymentRoot = "AccessWeaver"
const deploymentRecord = "deployment.json"
const deploymentLock = ".deployment.lock"
const maxRetainedDeployments = 64
const maxRetainedRecords = 128

var recordName = regexp.MustCompile(`^\.record-[a-f0-9]{32}$`)

// All constructors are private. The sealed CLI uses the fixed root authority;
// Apple package phases use the same authority. Only owned
// in-package native fixtures may supply a different parent/owner.
type deploymentStore struct {
	parent, root, versions, lock, current, runtimeLock *os.File
	owner                                              uint32
	state                                              deploymentState
	encoded                                            []byte
	// Native tests inject a stopped operation at durable phase boundaries.
	// There is no environment or configuration route to this callback.
	observe func(string) error
}

func openDeployment(initialize bool) (*deploymentStore, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("deployment mutation requires root")
	}
	parent, e := darwintrust.OpenRootDirectory(deploymentParent)
	if e != nil {
		return nil, e
	}
	return beginDeploymentMode(parent, 0, nil, initialize)
}
func deploymentDirectory(parent *os.File, name string, owner uint32, create bool) (*os.File, error) {
	f, e := darwintrust.OpenDirectoryAt(parent, name, owner)
	if errors.Is(e, unix.ENOENT) && create {
		f, e = darwintrust.CreateDirectoryAt(parent, name, owner)
		if errors.Is(e, unix.EEXIST) {
			return deploymentDirectory(parent, name, owner, false)
		}
		if e == nil {
			if owner == 0 {
				e = f.Chown(0, 0)
			}
			if e == nil {
				e = errors.Join(f.Chmod(0755), fullDeploymentSync(f), fullDeploymentSync(parent))
			}
		}
	}
	if e == nil {
		e = deploymentObject(f, true, owner, 0755)
	}
	if e != nil && f != nil {
		f.Close()
		f = nil
	}
	return f, e
}
func deploymentObject(f *os.File, dir bool, owner uint32, mode os.FileMode) error {
	info, e := darwintrust.Check(f, dir, owner)
	if e != nil {
		return e
	}
	if info.Mode().Perm() != mode {
		return errors.New("deployment object mode differs")
	}
	if owner == 0 && info.Sys().(*syscall.Stat_t).Gid != 0 {
		return errors.New("deployment object is not root:wheel")
	}
	return nil
}
func fullDeploymentSync(f *os.File) error {
	if e := f.Sync(); e != nil {
		return e
	}
	raw, e := f.SyscallConn()
	if e != nil {
		return e
	}
	var syncErr error
	e = raw.Control(func(fd uintptr) { _, syncErr = unix.FcntlInt(fd, unix.F_FULLFSYNC, 0) })
	return errors.Join(e, syncErr)
}
func randomDeploymentName() (string, error) {
	var value [16]byte
	if _, e := rand.Read(value[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(value[:]), nil
}
func sameDeploymentEntry(parent *os.File, name string, held *os.File, owner uint32) error {
	actual, e := darwintrust.OpenDirectoryAt(parent, name, owner)
	if e != nil {
		return e
	}
	defer actual.Close()
	a, e := held.Stat()
	if e != nil {
		return e
	}
	b, e := actual.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(a, b) {
		return errors.New("deployment directory identity changed")
	}
	return nil
}
func deploymentEntries(dir *os.File, owner uint32, limit int) ([]os.DirEntry, error) {
	// Fresh descriptor avoids sharing enumeration offsets with the held root.
	fd, e := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), dir.Name())
	defer f.Close()
	if _, e = darwintrust.Check(f, true, owner); e != nil {
		return nil, e
	}
	entries, e := f.ReadDir(limit + 1)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(entries) > limit {
		return nil, errors.New("retained deployment evidence capacity exhausted; preserve and inspect")
	}
	return entries, nil
}

// Parent ownership transfers on all paths. No unchecked caller path is used by
// the runtime constructor. Unknown/orphan state is retained, never scavenged.
func beginDeployment(parent *os.File, owner uint32, observe func(string) error) (*deploymentStore, error) {
	return beginDeploymentMode(parent, owner, observe, true)
}
func beginDeploymentMode(parent *os.File, owner uint32, observe func(string) error, initialize bool) (*deploymentStore, error) {
	s := &deploymentStore{parent: parent, owner: owner, observe: observe}
	fail := func(e error) (*deploymentStore, error) { return nil, errors.Join(e, s.Close()) }
	if _, e := darwintrust.Check(parent, true, owner); e != nil {
		return fail(e)
	}
	var e error
	s.root, e = deploymentDirectory(parent, deploymentRoot, owner, initialize)
	if e != nil {
		return fail(e)
	}
	// Inspect before creating coordination state: an existing unrecognized
	// directory must remain byte-for-byte untouched on bootstrap refusal.
	initialEntries, e := deploymentEntries(s.root, owner, maxRetainedRecords+4)
	if e != nil {
		return fail(e)
	}
	hasLock, hasVersions, hasHistory, hasState, hasRuntime := false, false, false, false, false
	for _, entry := range initialEntries {
		name := entry.Name()
		if name == deploymentLock {
			hasLock = true
			continue
		}
		if name == runtimeLeaseName {
			hasRuntime = true
			continue
		}
		if name == "versions" {
			hasVersions = true
		}
		if name == "state" {
			hasState = true
		}
		if name == "state" || recordName.MatchString(name) {
			hasHistory = true
		}
		if name != "versions" && name != "state" && !recordName.MatchString(name) {
			return fail(errors.New("unexpected deployment authority object"))
		}
	}
	if len(initialEntries) != 0 && !hasLock {
		return fail(errors.New("existing deployment history has no coordination file; preserve and inspect"))
	}
	if hasHistory && !hasRuntime {
		return fail(errors.New("deployment runtime coordination is absent; explicit maintenance migration is required"))
	}
	if hasHistory && !hasVersions {
		return fail(errors.New("existing deployment history has no versions directory; preserve and inspect"))
	}
	if !initialize && !hasState {
		return fail(errors.New("deployment state is absent; only prepare may initialize a new store"))
	}
	s.lock, e = darwintrust.CreateRegularAt(s.root, deploymentLock, owner)
	createdLock := e == nil
	if errors.Is(e, unix.EEXIST) {
		s.lock, e = darwintrust.OpenRegularAt(s.root, deploymentLock, owner)
	}
	if e != nil {
		return fail(e)
	}
	if e = deploymentObject(s.lock, false, owner, 0600); e != nil {
		return fail(e)
	}
	info, e := s.lock.Stat()
	if e != nil {
		return fail(e)
	}
	if info.Size() != 0 {
		return fail(errors.New("deployment lock is not empty"))
	}
	if createdLock {
		if e = errors.Join(fullDeploymentSync(s.lock), fullDeploymentSync(s.root)); e != nil {
			return fail(e)
		}
	}
	if e = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fail(fmt.Errorf("deployment is busy: %w", e))
	}
	actual, e := darwintrust.OpenRegularAt(s.root, deploymentLock, owner)
	if e != nil {
		return fail(e)
	}
	other, statErr := actual.Stat()
	closeErr := actual.Close()
	if e = errors.Join(statErr, closeErr); e != nil {
		return fail(e)
	}
	if !os.SameFile(info, other) {
		return fail(errors.New("deployment lock identity changed"))
	}
	if e = s.checkRoot(); e != nil {
		return fail(e)
	}
	entries, e := deploymentEntries(s.root, owner, maxRetainedRecords+4)
	if e != nil {
		return fail(e)
	}
	history := 0
	for _, entry := range entries {
		name := entry.Name()
		if name == deploymentLock || name == runtimeLeaseName || name == "versions" || name == "state" {
			continue
		}
		if !recordName.MatchString(name) {
			return fail(errors.New("unexpected deployment authority object"))
		}
		history++
	}
	s.runtimeLock, e = darwintrust.CreateRegularAt(s.root, runtimeLeaseName, owner)
	createdRuntime := e == nil
	if errors.Is(e, unix.EEXIST) {
		s.runtimeLock, e = darwintrust.OpenRegularAt(s.root, runtimeLeaseName, owner)
	}
	if e != nil {
		return fail(e)
	}
	if createdRuntime {
		if e = errors.Join(s.runtimeLock.Chmod(0644), fullDeploymentSync(s.runtimeLock), fullDeploymentSync(s.root)); e != nil {
			return fail(e)
		}
	}
	if e = deploymentObject(s.runtimeLock, false, owner, 0644); e != nil {
		return fail(e)
	}
	runtimeInfo, e := s.runtimeLock.Stat()
	if e != nil {
		return fail(e)
	}
	if runtimeInfo.Size() != 0 {
		return fail(errors.New("deployment runtime coordination file is not empty"))
	}
	if e = unix.Flock(int(s.runtimeLock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fail(fmt.Errorf("AccessWeaver is running; close it before changing this installation: %w", e))
	}
	currentRuntime, e := darwintrust.OpenRegularAt(s.root, runtimeLeaseName, owner)
	if e != nil {
		return fail(e)
	}
	currentInfo, statErr := currentRuntime.Stat()
	closeErr = currentRuntime.Close()
	if e = errors.Join(statErr, closeErr); e != nil {
		return fail(e)
	}
	if !os.SameFile(runtimeInfo, currentInfo) {
		return fail(errors.New("runtime coordination identity changed"))
	}
	s.versions, e = deploymentDirectory(s.root, "versions", owner, initialize && !hasHistory)
	if e != nil {
		return fail(e)
	}
	s.current, e = deploymentDirectory(s.root, "state", owner, false)
	if errors.Is(e, unix.ENOENT) {
		slots, readErr := deploymentEntries(s.versions, owner, maxRetainedDeployments)
		if readErr != nil {
			return fail(readErr)
		}
		if len(slots) != 0 || history != 0 {
			return fail(errors.New("missing deployment record with retained history; preserve for recovery"))
		}
		s.state = emptyDeployment()
		if _, e = s.commit(s.state); e != nil {
			return fail(e)
		}
	} else if e != nil {
		return fail(e)
	} else {
		s.encoded, e = s.readRecord(s.current)
		if e != nil {
			return fail(e)
		}
		s.state, e = decodeDeployment(s.encoded)
		if e != nil {
			return fail(e)
		}
	}
	return s, nil
}
func (s *deploymentStore) checkRoot() error {
	if s.root == nil || s.lock == nil {
		return errors.New("deployment store is closed")
	}
	if e := sameDeploymentEntry(s.parent, deploymentRoot, s.root, s.owner); e != nil {
		return e
	}
	if e := deploymentObject(s.root, true, s.owner, 0755); e != nil {
		return e
	}
	if s.versions != nil {
		if e := sameDeploymentEntry(s.root, "versions", s.versions, s.owner); e != nil {
			return e
		}
	}
	actual, e := darwintrust.OpenRegularAt(s.root, deploymentLock, s.owner)
	if e != nil {
		return e
	}
	defer actual.Close()
	if e = deploymentObject(actual, false, s.owner, 0600); e != nil {
		return e
	}
	before, e := s.lock.Stat()
	if e != nil {
		return e
	}
	after, e := actual.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(before, after) || after.Size() != 0 {
		return errors.New("deployment lock identity changed")
	}
	if s.runtimeLock != nil {
		if e := sameRuntimeFile(s.root, s.runtimeLock, s.owner); e != nil {
			return e
		}
	}
	return nil
}
func (s *deploymentStore) phase(name string) error {
	if s.observe != nil {
		return s.observe(name)
	}
	return nil
}
func (s *deploymentStore) readRecord(dir *os.File) ([]byte, error) {
	entries, e := deploymentEntries(dir, s.owner, 1)
	if e != nil {
		return nil, e
	}
	if len(entries) != 1 || entries[0].Name() != deploymentRecord {
		return nil, errors.New("deployment record inventory differs")
	}
	f, e := darwintrust.OpenRegularAt(dir, deploymentRecord, s.owner)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if e = deploymentObject(f, false, s.owner, 0644); e != nil {
		return nil, e
	}
	before, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if before.Size() > maxDeploymentRecord || before.Size() < 0 {
		return nil, errors.New("deployment record exceeds limit")
	}
	data, e := io.ReadAll(io.LimitReader(f, maxDeploymentRecord+1))
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !sameState(*before.Sys().(*syscall.Stat_t), *after.Sys().(*syscall.Stat_t)) || int64(len(data)) != before.Size() {
		return nil, errors.New("deployment record changed while reading")
	}
	return data, nil
}

// commit returns published even if a post-rename durability/error probe fails.
// Callers must reopen/reconcile, never undo a possibly published generation.
func (s *deploymentStore) commit(next deploymentState) (published bool, result error) {
	encoded, e := encodeDeployment(next)
	if e != nil {
		return false, e
	}
	if e = s.checkRoot(); e != nil {
		return false, e
	}
	if s.current != nil {
		if e = sameDeploymentEntry(s.root, "state", s.current, s.owner); e != nil {
			return false, e
		}
		actual, e := s.readRecord(s.current)
		if e != nil {
			return false, e
		}
		if !bytes.Equal(actual, s.encoded) {
			return false, errors.New("deployment preimage changed")
		}
	}
	entries, e := deploymentEntries(s.root, s.owner, maxRetainedRecords+4)
	if e != nil {
		return false, e
	}
	count := 0
	for _, entry := range entries {
		if recordName.MatchString(entry.Name()) {
			count++
		}
	}
	if count >= maxRetainedRecords {
		return false, errors.New("retained deployment record capacity exhausted; preserve and inspect")
	}
	nonce, e := randomDeploymentName()
	if e != nil {
		return false, e
	}
	name := ".record-" + nonce
	staged, e := darwintrust.CreateDirectoryAt(s.root, name, s.owner)
	if e != nil {
		return false, e
	}
	defer func() {
		if staged != nil {
			result = errors.Join(result, staged.Close())
		}
	}()
	if e = s.phase("record-reserved"); e != nil {
		return false, e
	}
	f, e := darwintrust.CreateRegularAt(staged, deploymentRecord, s.owner)
	if e != nil {
		return false, e
	}
	n, writeErr := f.Write(encoded)
	if writeErr == nil && n != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	e = errors.Join(writeErr, f.Chmod(0644), fullDeploymentSync(f), f.Close())
	if e != nil {
		return false, e
	}
	if e = s.phase("record-file-durable"); e != nil {
		return false, e
	}
	if e = errors.Join(staged.Chmod(0755), fullDeploymentSync(staged)); e != nil {
		return false, e
	}
	if e = s.phase("record-directory-durable"); e != nil {
		return false, e
	}
	actual, e := s.readRecord(staged)
	if e != nil {
		return false, e
	}
	if !bytes.Equal(actual, encoded) {
		return false, errors.New("staged deployment record changed")
	}
	if e = sameDeploymentEntry(s.root, name, staged, s.owner); e != nil {
		return false, e
	}
	if e = s.checkRoot(); e != nil {
		return false, e
	}
	if e = darwintrust.RenameDirectories(s.root, name, "state", s.current != nil); e != nil {
		return false, e
	}
	old := s.current
	s.current = staged
	staged = nil
	s.state = next
	s.encoded = encoded
	var closeErr error
	if old != nil {
		closeErr = old.Close()
	}
	if e = s.phase("record-published"); e != nil {
		return true, errors.Join(e, closeErr)
	}
	e = errors.Join(fullDeploymentSync(s.root), closeErr)
	if e != nil {
		return true, e
	}
	return true, s.phase("record-parent-durable")
}
func slotFromDirectory(f *os.File, id string, identity deploymentIdentity) (deploymentSlot, error) {
	info, e := f.Stat()
	if e != nil {
		return deploymentSlot{}, e
	}
	st := info.Sys().(*syscall.Stat_t)
	return deploymentSlot{ID: id, Device: int64(st.Dev), Inode: st.Ino, Identity: identity}, nil
}
func (s *deploymentStore) prepare(identity deploymentIdentity) (deploymentSlot, error) {
	if e := identity.validate(); e != nil {
		return deploymentSlot{}, e
	}
	// Capacity/downgrade refusal must occur before reserving a filesystem slot.
	if e := s.state.canPrepare(identity); e != nil {
		return deploymentSlot{}, e
	}
	if e := s.checkRoot(); e != nil {
		return deploymentSlot{}, e
	}
	entries, e := deploymentEntries(s.versions, s.owner, maxRetainedDeployments)
	if e != nil {
		return deploymentSlot{}, e
	}
	if len(entries) >= maxRetainedDeployments {
		return deploymentSlot{}, errors.New("retained deployment slot capacity exhausted; preserve and inspect")
	}
	id, e := randomDeploymentName()
	if e != nil {
		return deploymentSlot{}, e
	}
	dir, e := darwintrust.CreateDirectoryAt(s.versions, id, s.owner)
	if e != nil {
		return deploymentSlot{}, e
	}
	defer dir.Close()
	slot, e := slotFromDirectory(dir, id, identity)
	if e != nil {
		return slot, e
	}
	if e = errors.Join(fullDeploymentSync(dir), fullDeploymentSync(s.versions)); e != nil {
		return slot, e
	}
	if e = s.phase("slot-reserved"); e != nil {
		return slot, e
	}
	next, e := s.state.prepare(slot)
	if e != nil {
		return slot, e
	}
	_, e = s.commit(next)
	return slot, e
}
func (s *deploymentStore) openSlot(slot deploymentSlot) (*os.File, error) {
	if e := slot.validate(); e != nil {
		return nil, e
	}
	dir, e := darwintrust.OpenDirectoryAt(s.versions, slot.ID, s.owner)
	if e != nil {
		return nil, e
	}
	actual, e := slotFromDirectory(dir, slot.ID, slot.Identity)
	if e == nil && actual != slot {
		e = errors.New("reserved deployment slot identity changed")
	}
	if e != nil {
		dir.Close()
		return nil, e
	}
	return dir, nil
}
func (s *deploymentStore) deactivate() (bool, error) {
	next, e := s.state.deactivate()
	if e != nil {
		return false, e
	}
	return s.commit(next)
}
func (s *deploymentStore) abandon(id string) (bool, error) {
	next, e := s.state.abandon(id)
	if e != nil {
		return false, e
	}
	return s.commit(next)
}
func (s *deploymentStore) Close() error {
	var result error
	for _, p := range []**os.File{&s.current, &s.runtimeLock, &s.lock, &s.versions, &s.root, &s.parent} {
		if *p != nil {
			result = errors.Join(result, (*p).Close())
			*p = nil
		}
	}
	return result
}
