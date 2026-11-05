//go:build darwin && (amd64 || arm64)

package audit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

const darwinAuditPathBytes = 1023
const darwinAuditPathComponents = 128
const darwinAuditComponentBytes = 255

// Directory ancestry may cross the protected System/Data firmlink boundary.
// These flags are allowed only on ancestors and are retained in each binding.
// Private final objects always require Flags==0; no flags are ever cleared.
const darwinAuditAncestorFlags = unix.UF_NODUMP | unix.UF_HIDDEN | unix.SF_RESTRICTED | unix.SF_FIRMLINK

type darwinAuditIdentity struct {
	dev int32
	ino uint64
}

type darwinAuditFilesystem struct {
	id                          [2]int32
	kind, flags, subtype, owner uint32
	name                        [16]byte
}

// Size and timestamps are observations, not a frozen baseline across authorized
// writes. A future writer must compare the appropriate pre/post observations.
type darwinAuditFileState struct {
	id                          darwinAuditIdentity
	filesystem                  darwinAuditFilesystem
	size                        int64
	modified, changed           unix.Timespec
	mode, links                 uint16
	uid, gid, flags, generation uint32
}

type darwinAuditDirectoryState struct {
	id                          darwinAuditIdentity
	filesystem                  darwinAuditFilesystem
	mode                        uint16
	uid, gid, flags, generation uint32
}

type darwinAuditDirectoryBinding struct {
	file, parent *os.File // parent is nil only for the fixed / binding.
	name         string
	state        darwinAuditDirectoryState
}

// This internal foundation owns every descriptor from / through an existing
// private directory. Native child opens use only its retained parent and name.
// The executing UID and root remain trusted. No method creates/repairs parents,
// deletes a partial object, syncs a parent, or establishes write durability.
// Metadata/path lookup can trigger OS automount before postlookup refusal;
// Openat and these observations do not establish nonhydrating metadata lookup.
// Methods serialize with Close. Returned data handles belong to the caller,
// which must retain this scope and recheck fileState around its own data I/O.
type darwinAuditDirectory struct {
	mu          sync.Mutex
	dir         *os.File
	owner       uint32
	principal   processPrincipal
	credentials [4]int
	ancestors   []darwinAuditDirectoryBinding
	closed      bool
	closeErr    error
}

func parseDarwinAuditPath(path string) ([]string, error) {
	if !utf8.ValidString(path) || len(path) == 0 || len(path) > darwinAuditPathBytes || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrJournalStorage
	}
	if path == "/" {
		return nil, nil
	}
	parts := strings.Split(path[1:], "/")
	if len(parts) > darwinAuditPathComponents {
		return nil, ErrJournalStorage
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > darwinAuditComponentBytes {
			return nil, ErrJournalStorage
		}
	}
	return parts, nil
}

func darwinAuditChild(name string) bool { return name == actorKeyName || name == journalName }

// Control retains each borrowed descriptor through every native operation. Raw
// native errors and private names are never returned through this boundary.
func darwinAuditControl(file *os.File, operation func(int) error) error {
	if file == nil {
		return ErrJournalStorage
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return ErrJournalStorage
	}
	var result error
	controlErr := raw.Control(func(fd uintptr) { result = operation(int(fd)) })
	if result != nil || controlErr != nil {
		return ErrJournalStorage
	}
	return nil
}

func darwinAuditStatState(stat *unix.Stat_t) darwinAuditFileState {
	return darwinAuditFileState{id: darwinAuditIdentity{stat.Dev, stat.Ino}, size: stat.Size, modified: stat.Mtim, changed: stat.Ctim, mode: stat.Mode, links: stat.Nlink, uid: stat.Uid, gid: stat.Gid, flags: stat.Flags, generation: stat.Gen}
}

func darwinAuditMetadata(file *os.File) (state darwinAuditFileState, failure error) {
	failure = darwinAuditControl(file, func(fd int) error {
		var stat unix.Stat_t
		var fs unix.Statfs_t
		if unix.Fstat(fd, &stat) != nil || unix.Fstatfs(fd, &fs) != nil {
			return ErrJournalStorage
		}
		state = darwinAuditStatState(&stat)
		state.filesystem = darwinAuditFilesystem{id: fs.Fsid.Val, kind: fs.Type, flags: fs.Flags, subtype: fs.Fssubtype, owner: fs.Owner}
		for i, value := range fs.Fstypename {
			state.filesystem.name[i] = byte(value)
		}
		if strings.TrimRight(string(state.filesystem.name[:]), "\x00") != "apfs" || fs.Flags&unix.MNT_LOCAL == 0 || fs.Flags&(unix.MNT_IGNORE_OWNERSHIP|unix.MNT_AUTOMOUNTED) != 0 || state.id.ino == 0 {
			return ErrJournalStorage
		}
		return nil
	})
	if failure != nil {
		return darwinAuditFileState{}, failure
	}
	return state, nil
}

func darwinAuditDirectorySecurity(state darwinAuditFileState, owner uint32, private bool) bool {
	if state.mode&unix.S_IFMT != unix.S_IFDIR || state.links == 0 || (state.uid != 0 && state.uid != owner) || state.mode&(0022|unix.S_ISUID|unix.S_ISGID) != 0 {
		return false
	}
	if private {
		return state.uid == owner && state.mode&07777 == 0700 && state.flags == 0
	}
	return state.flags & ^uint32(darwinAuditAncestorFlags) == 0 && (state.flags&unix.SF_FIRMLINK == 0 || state.uid == 0)
}

func darwinAuditInspectDirectory(file *os.File, owner uint32, private bool) (darwinAuditDirectoryState, error) {
	var zero darwinAuditDirectoryState
	before, err := darwinAuditMetadata(file)
	if err != nil || !darwinAuditDirectorySecurity(before, owner, private) {
		return zero, ErrJournalStorage
	}
	if private {
		err = darwintrust.CheckEmptyACL(file)
	} else {
		err = darwintrust.CheckReadOnlyACL(file)
	}
	if err != nil {
		return zero, ErrJournalStorage
	}
	after, err := darwinAuditMetadata(file)
	if err != nil || after != before {
		return zero, ErrJournalStorage
	}
	return darwinAuditDirectoryState{id: after.id, filesystem: after.filesystem, mode: after.mode, uid: after.uid, gid: after.gid, flags: after.flags, generation: after.generation}, nil
}

func darwinAuditOpenAt(parent *os.File, name string, flags int, mode uint32) (file *os.File, failure error) {
	fd := -1
	failure = darwinAuditControl(parent, func(parentFD int) error {
		var err error
		fd, err = unix.Openat(parentFD, name, flags, mode)
		return err
	})
	if fd >= 0 {
		file = os.NewFile(uintptr(fd), "audit-bound-object")
	}
	if failure != nil || file == nil {
		if file != nil {
			_ = file.Close()
		} else if fd >= 0 {
			_ = unix.Close(fd)
		}
		return nil, ErrJournalStorage
	}
	return file, nil
}

func darwinAuditNamedState(parent *os.File, name string) (state darwinAuditFileState, failure error) {
	failure = darwinAuditControl(parent, func(fd int) error {
		var stat unix.Stat_t
		if unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return ErrJournalStorage
		}
		state = darwinAuditStatState(&stat)
		return nil
	})
	if failure != nil {
		return darwinAuditFileState{}, failure
	}
	return state, nil
}

func openDarwinAuditDirectory(path string) (result *darwinAuditDirectory, failure error) {
	parts, err := parseDarwinAuditPath(path)
	if err != nil {
		return nil, err
	}
	credentials := credentialSnapshot()
	principal, err := currentProcessPrincipal()
	if err != nil || credentials != credentialSnapshot() || uint64(credentials[1]) > uint64(^uint32(0)) {
		return nil, ErrProcessIdentity
	}
	d := &darwinAuditDirectory{owner: uint32(credentials[1]), principal: principal, credentials: credentials}
	defer func() {
		if d.checkPrincipalLocked() != nil {
			result, failure = nil, ErrProcessIdentity
		}
		if result == nil {
			closeErr := d.Close()
			if closeErr == ErrProcessIdentity {
				failure = ErrProcessIdentity
			} else if closeErr != nil && failure != ErrProcessIdentity {
				failure = ErrJournalStorage
			}
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrJournalStorage
	}
	root := os.NewFile(uintptr(fd), "audit-fixed-root")
	if root == nil {
		_ = unix.Close(fd)
		return nil, ErrJournalStorage
	}
	d.ancestors = append(d.ancestors, darwinAuditDirectoryBinding{file: root, name: "/"})
	for index := 0; index <= len(parts); index++ {
		binding := &d.ancestors[index]
		state, err := darwinAuditInspectDirectory(binding.file, d.owner, index == len(parts))
		if err != nil {
			return nil, err
		}
		binding.state = state
		if index == len(parts) {
			d.dir = binding.file
			break
		}
		before, err := darwinAuditNamedState(binding.file, parts[index])
		if err != nil || !darwinAuditDirectorySecurity(before, d.owner, index+1 == len(parts)) {
			return nil, ErrJournalStorage
		}
		child, err := darwinAuditOpenAt(binding.file, parts[index], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		// Keep ownership even when the next inspection fails.
		d.ancestors = append(d.ancestors, darwinAuditDirectoryBinding{file: child, parent: binding.file, name: parts[index]})
		opened, err := darwinAuditMetadata(child)
		if err != nil || opened.id != before.id {
			return nil, ErrJournalStorage
		}
	}
	if err := d.checkBindingLocked(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *darwinAuditDirectory) checkPrincipalLocked() error {
	before := credentialSnapshot()
	principal, err := currentProcessPrincipal()
	if err != nil || principal != d.principal || before != d.credentials || credentialSnapshot() != d.credentials {
		return ErrProcessIdentity
	}
	return nil
}

func (d *darwinAuditDirectory) reopenBindingLocked(binding darwinAuditDirectoryBinding, private bool) (*os.File, error) {
	if binding.parent == nil {
		if binding.name != "/" {
			return nil, ErrJournalStorage
		}
		fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrJournalStorage
		}
		file := os.NewFile(uintptr(fd), "audit-root-probe")
		if file == nil {
			_ = unix.Close(fd)
			return nil, ErrJournalStorage
		}
		return file, nil
	}
	before, err := darwinAuditNamedState(binding.parent, binding.name)
	if err != nil || !darwinAuditDirectorySecurity(before, d.owner, private) || before.id != binding.state.id {
		return nil, ErrJournalStorage
	}
	return darwinAuditOpenAt(binding.parent, binding.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func (d *darwinAuditDirectory) checkBindingLocked() error {
	if d.closed || d.dir == nil || len(d.ancestors) == 0 || d.dir != d.ancestors[len(d.ancestors)-1].file {
		return ErrJournalStorage
	}
	for index, binding := range d.ancestors {
		private := index == len(d.ancestors)-1
		if index == 0 && (binding.parent != nil || binding.name != "/") || index > 0 && binding.parent != d.ancestors[index-1].file {
			return ErrJournalStorage
		}
		state, err := darwinAuditInspectDirectory(binding.file, d.owner, private)
		if err != nil || state != binding.state {
			return ErrJournalStorage
		}
		probe, err := d.reopenBindingLocked(binding, private)
		if err != nil {
			return err
		}
		named, statErr := darwinAuditInspectDirectory(probe, d.owner, private)
		closeErr := probe.Close()
		if statErr != nil || closeErr != nil || named != binding.state {
			return ErrJournalStorage
		}
	}
	return nil
}

func (d *darwinAuditDirectory) checkBinding() (failure error) {
	if d == nil {
		return ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.checkPrincipalLocked() != nil {
		return ErrProcessIdentity
	}
	defer func() {
		if d.checkPrincipalLocked() != nil {
			failure = ErrProcessIdentity
		}
	}()
	return d.checkBindingLocked()
}

func (d *darwinAuditDirectory) privateFileSecurity(state darwinAuditFileState, name string) bool {
	limit := int64(MaxJournalBytes)
	if name == actorKeyName {
		limit = int64(actorKeyFileBytes)
	}
	return darwinAuditChild(name) && state.mode&unix.S_IFMT == unix.S_IFREG && state.mode&07777 == 0600 && state.links == 1 && state.uid == d.owner && state.flags == 0 && state.id.dev == d.ancestors[len(d.ancestors)-1].state.id.dev && state.size >= 0 && state.size <= limit
}

func (d *darwinAuditDirectory) inspectPrivateFileLocked(file *os.File, name string) (darwinAuditFileState, error) {
	var zero darwinAuditFileState
	before, err := darwinAuditMetadata(file)
	if err != nil || !d.privateFileSecurity(before, name) || before.filesystem != d.ancestors[len(d.ancestors)-1].state.filesystem || darwintrust.CheckEmptyACL(file) != nil {
		return zero, ErrJournalStorage
	}
	after, err := darwinAuditMetadata(file)
	if err != nil || after != before {
		return zero, ErrJournalStorage
	}
	return after, nil
}

func (d *darwinAuditDirectory) fileStateLocked(file *os.File, name string) (darwinAuditFileState, error) {
	var zero darwinAuditFileState
	if !darwinAuditChild(name) || d.checkBindingLocked() != nil {
		return zero, ErrJournalStorage
	}
	held, err := d.inspectPrivateFileLocked(file, name)
	if err != nil {
		return zero, err
	}
	named, err := darwinAuditNamedState(d.dir, name)
	if err != nil || !d.privateFileSecurity(named, name) {
		return zero, ErrJournalStorage
	}
	// Fstatat supplies metadata without opening an attacker-selected special file.
	named.filesystem = held.filesystem
	if named != held {
		return zero, ErrJournalStorage
	}
	after, err := d.inspectPrivateFileLocked(file, name)
	if err != nil || after != held || d.checkBindingLocked() != nil {
		return zero, ErrJournalStorage
	}
	return after, nil
}

func (d *darwinAuditDirectory) fileState(file *os.File, name string) (state darwinAuditFileState, failure error) {
	if d == nil {
		return state, ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.checkPrincipalLocked() != nil {
		return state, ErrProcessIdentity
	}
	defer func() {
		if d.checkPrincipalLocked() != nil {
			state, failure = darwinAuditFileState{}, ErrProcessIdentity
		}
	}()
	return d.fileStateLocked(file, name)
}

func (d *darwinAuditDirectory) createRegular(name string) (*os.File, error) {
	return d.openRegularUsing(name, true, true)
}
func (d *darwinAuditDirectory) openRegular(name string, writable bool) (*os.File, error) {
	return d.openRegularUsing(name, writable, false)
}

func (d *darwinAuditDirectory) openRegularUsing(name string, writable, create bool) (result *os.File, failure error) {
	if d == nil || !darwinAuditChild(name) {
		return nil, ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.checkPrincipalLocked() != nil {
		return nil, ErrProcessIdentity
	}
	defer func() {
		if d.checkPrincipalLocked() != nil {
			if result != nil {
				_ = result.Close()
			}
			result, failure = nil, ErrProcessIdentity
		}
	}()
	if err := d.checkBindingLocked(); err != nil {
		return nil, err
	}
	var before darwinAuditFileState
	if !create {
		var err error
		before, err = darwinAuditNamedState(d.dir, name)
		if err != nil || !d.privateFileSecurity(before, name) {
			return nil, ErrJournalStorage
		}
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC
	if writable {
		flags = (flags & ^unix.O_RDONLY) | unix.O_RDWR
	}
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	// Recheck the private parent's empty ACL immediately before exclusive create.
	if err := d.checkBindingLocked(); err != nil {
		return nil, err
	}
	file, err := darwinAuditOpenAt(d.dir, name, flags, 0600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil && file.Close() != nil && failure != ErrProcessIdentity {
			failure = ErrJournalStorage
		}
	}()
	if create {
		initial, err := darwinAuditMetadata(file)
		if err != nil || initial.mode&unix.S_IFMT != unix.S_IFREG || initial.mode&07777 & ^uint16(0600) != 0 || initial.links != 1 || initial.uid != d.owner || initial.flags != 0 || initial.size != 0 || initial.id.dev != d.ancestors[len(d.ancestors)-1].state.id.dev || initial.filesystem != d.ancestors[len(d.ancestors)-1].state.filesystem {
			return nil, ErrJournalStorage
		}
		// Only this exclusively created, still-empty object may be normalized. No
		// secret payload is written here, and every failed object remains on disk.
		if darwintrust.ResetCreatedACL(file) != nil || darwinAuditControl(file, func(fd int) error { return unix.Fchmod(fd, 0600) }) != nil {
			return nil, ErrJournalStorage
		}
		after, err := d.fileStateLocked(file, name)
		if err != nil || after.id != initial.id || after.size != 0 {
			return nil, ErrJournalStorage
		}
	} else {
		opened, err := d.fileStateLocked(file, name)
		before.filesystem = opened.filesystem
		if err != nil || opened != before {
			return nil, ErrJournalStorage
		}
	}
	return file, nil
}

func (d *darwinAuditDirectory) requireEmpty() (failure error) {
	if d == nil {
		return ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.checkPrincipalLocked() != nil {
		return ErrProcessIdentity
	}
	defer func() {
		if d.checkBindingLocked() != nil && failure == nil {
			failure = ErrJournalStorage
		}
		if d.checkPrincipalLocked() != nil {
			failure = ErrProcessIdentity
		}
	}()
	if err := d.checkBindingLocked(); err != nil {
		return err
	}
	last := d.ancestors[len(d.ancestors)-1]
	iterator, err := d.reopenBindingLocked(last, true)
	if err != nil {
		return err
	}
	defer func() {
		if iterator.Close() != nil && failure == nil {
			failure = ErrJournalStorage
		}
	}()
	state, err := darwinAuditInspectDirectory(iterator, d.owner, true)
	if err != nil || state != last.state {
		return ErrJournalStorage
	}
	names, readErr := iterator.Readdirnames(1)
	if len(names) != 0 || !errors.Is(readErr, io.EOF) {
		return ErrJournalStorage
	}
	after, err := darwinAuditInspectDirectory(iterator, d.owner, true)
	if err != nil || after != state {
		return ErrJournalStorage
	}
	return nil
}

// Close attempts every owned ancestor close even after binding/credential
// refusal, never closes caller-owned data handles, and preserves its result.
func (d *darwinAuditDirectory) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return d.closeErr
	}
	if d.checkPrincipalLocked() != nil {
		d.closeErr = ErrProcessIdentity
	} else if d.dir != nil && d.checkBindingLocked() != nil {
		d.closeErr = ErrJournalStorage
	}
	d.closed = true
	for index := len(d.ancestors) - 1; index >= 0; index-- {
		if d.ancestors[index].file != nil && d.ancestors[index].file.Close() != nil && d.closeErr == nil {
			d.closeErr = ErrJournalStorage
		}
	}
	d.dir = nil
	if d.checkPrincipalLocked() != nil {
		d.closeErr = ErrProcessIdentity
	}
	return d.closeErr
}
