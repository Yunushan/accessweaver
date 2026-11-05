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
const darwinAuditAncestorFlags = unix.UF_NODUMP | unix.UF_HIDDEN | unix.SF_RESTRICTED | unix.SF_FIRMLINK | unix.SF_NOUNLINK

// Rejection codes describe only fixed source branches. Their public error
// text and sentinel identity stay generic; no observed metadata is retained.
type darwinAuditRejectionCode uint8

const (
	darwinAuditRejectNilDescriptor darwinAuditRejectionCode = iota + 1
	darwinAuditRejectSyscallConnection
	darwinAuditRejectControl
	darwinAuditRejectNativeOperation
	darwinAuditRejectFstat
	darwinAuditRejectFstatfs
	darwinAuditRejectFilesystemName
	darwinAuditRejectFilesystemNonlocal
	darwinAuditRejectFilesystemIgnoreOwnership
	darwinAuditRejectFilesystemAutomounted
	darwinAuditRejectZeroInode
	darwinAuditRejectDirectoryType
	darwinAuditRejectDirectoryLink
	darwinAuditRejectDirectoryOwner
	darwinAuditRejectDirectoryMode
	darwinAuditRejectPrivateDirectoryFlags
	darwinAuditRejectAncestorNoUnlink // Historical d80122f code; protected ancestors now admit this flag.
	darwinAuditRejectAncestorFlags
	darwinAuditRejectFirmlinkOwner
	darwinAuditRejectAncestorACL
	darwinAuditRejectPrivateACL
	darwinAuditRejectMetadataIdentity
	darwinAuditRejectMetadataFilesystem
	darwinAuditRejectMetadataSize
	darwinAuditRejectMetadataTimes
	darwinAuditRejectMetadataSecurity
	darwinAuditRejectMetadataOther
	darwinAuditRejectRootOpen
	darwinAuditRejectRootRetain
	darwinAuditRejectPath
	darwinAuditRejectFstatat
	darwinAuditRejectOpenat
	darwinAuditRejectOpenRetain
	darwinAuditRejectOpenedIdentity
	darwinAuditRejectScopeState
	darwinAuditRejectParentBinding
	darwinAuditRejectSavedBinding
	darwinAuditRejectReopenedState
	darwinAuditRejectProbeClose
	darwinAuditRejectOwnedClose
)

type darwinAuditRejection struct{ code darwinAuditRejectionCode }

func (*darwinAuditRejection) Error() string { return ErrJournalStorage.Error() }
func (*darwinAuditRejection) Unwrap() error { return ErrJournalStorage }
func (rejection *darwinAuditRejection) rejectionCode() string {
	if rejection == nil {
		return ""
	}
	switch rejection.code {
	case darwinAuditRejectNilDescriptor:
		return "nil-descriptor"
	case darwinAuditRejectSyscallConnection:
		return "syscall-connection"
	case darwinAuditRejectControl:
		return "descriptor-control"
	case darwinAuditRejectNativeOperation:
		return "native-operation"
	case darwinAuditRejectFstat:
		return "fstat"
	case darwinAuditRejectFstatfs:
		return "fstatfs"
	case darwinAuditRejectFilesystemName:
		return "filesystem-name"
	case darwinAuditRejectFilesystemNonlocal:
		return "filesystem-nonlocal"
	case darwinAuditRejectFilesystemIgnoreOwnership:
		return "filesystem-ignore-ownership"
	case darwinAuditRejectFilesystemAutomounted:
		return "filesystem-automounted"
	case darwinAuditRejectZeroInode:
		return "zero-inode"
	case darwinAuditRejectDirectoryType:
		return "directory-type"
	case darwinAuditRejectDirectoryLink:
		return "directory-link"
	case darwinAuditRejectDirectoryOwner:
		return "directory-owner"
	case darwinAuditRejectDirectoryMode:
		return "directory-mode"
	case darwinAuditRejectPrivateDirectoryFlags:
		return "private-directory-flags"
	case darwinAuditRejectAncestorNoUnlink:
		return "ancestor-nounlink"
	case darwinAuditRejectAncestorFlags:
		return "ancestor-flags"
	case darwinAuditRejectFirmlinkOwner:
		return "firmlink-owner"
	case darwinAuditRejectAncestorACL:
		return "ancestor-acl"
	case darwinAuditRejectPrivateACL:
		return "private-acl"
	case darwinAuditRejectMetadataIdentity:
		return "metadata-identity"
	case darwinAuditRejectMetadataFilesystem:
		return "metadata-filesystem"
	case darwinAuditRejectMetadataSize:
		return "metadata-size"
	case darwinAuditRejectMetadataTimes:
		return "metadata-times"
	case darwinAuditRejectMetadataSecurity:
		return "metadata-security"
	case darwinAuditRejectMetadataOther:
		return "metadata-other"
	case darwinAuditRejectRootOpen:
		return "root-open"
	case darwinAuditRejectRootRetain:
		return "root-retain"
	case darwinAuditRejectPath:
		return "path"
	case darwinAuditRejectFstatat:
		return "fstatat"
	case darwinAuditRejectOpenat:
		return "openat"
	case darwinAuditRejectOpenRetain:
		return "open-retain"
	case darwinAuditRejectOpenedIdentity:
		return "opened-identity"
	case darwinAuditRejectScopeState:
		return "scope-state"
	case darwinAuditRejectParentBinding:
		return "parent-binding"
	case darwinAuditRejectSavedBinding:
		return "saved-binding"
	case darwinAuditRejectReopenedState:
		return "reopened-state"
	case darwinAuditRejectProbeClose:
		return "probe-close"
	case darwinAuditRejectOwnedClose:
		return "owned-close"
	default:
		return ""
	}
}
func darwinAuditRejected(code darwinAuditRejectionCode) error {
	rejection := &darwinAuditRejection{code: code}
	if rejection.rejectionCode() == "" {
		return ErrJournalStorage
	}
	return rejection
}
func darwinAuditStorageRejection(err error) error {
	var rejection *darwinAuditRejection
	if errors.As(err, &rejection) && rejection.rejectionCode() != "" {
		return rejection
	}
	return ErrJournalStorage
}

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
		return nil, darwinAuditRejected(darwinAuditRejectPath)
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
		return darwinAuditRejected(darwinAuditRejectNilDescriptor)
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return darwinAuditRejected(darwinAuditRejectSyscallConnection)
	}
	var result error
	controlErr := raw.Control(func(fd uintptr) { result = operation(int(fd)) })
	if result != nil || controlErr != nil {
		if result != nil {
			var rejection *darwinAuditRejection
			if errors.As(result, &rejection) && rejection.rejectionCode() != "" {
				return rejection
			}
			return darwinAuditRejected(darwinAuditRejectNativeOperation)
		}
		return darwinAuditRejected(darwinAuditRejectControl)
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
		if unix.Fstat(fd, &stat) != nil {
			return darwinAuditRejected(darwinAuditRejectFstat)
		}
		if unix.Fstatfs(fd, &fs) != nil {
			return darwinAuditRejected(darwinAuditRejectFstatfs)
		}
		state = darwinAuditStatState(&stat)
		state.filesystem = darwinAuditFilesystem{id: fs.Fsid.Val, kind: fs.Type, flags: fs.Flags, subtype: fs.Fssubtype, owner: fs.Owner}
		for i, value := range fs.Fstypename {
			state.filesystem.name[i] = byte(value)
		}
		if strings.TrimRight(string(state.filesystem.name[:]), "\x00") != "apfs" || fs.Flags&unix.MNT_LOCAL == 0 || fs.Flags&(unix.MNT_IGNORE_OWNERSHIP|unix.MNT_AUTOMOUNTED) != 0 || state.id.ino == 0 {
			if strings.TrimRight(string(state.filesystem.name[:]), "\x00") != "apfs" {
				return darwinAuditRejected(darwinAuditRejectFilesystemName)
			}
			if fs.Flags&unix.MNT_LOCAL == 0 {
				return darwinAuditRejected(darwinAuditRejectFilesystemNonlocal)
			}
			if fs.Flags&unix.MNT_IGNORE_OWNERSHIP != 0 {
				return darwinAuditRejected(darwinAuditRejectFilesystemIgnoreOwnership)
			}
			if fs.Flags&unix.MNT_AUTOMOUNTED != 0 {
				return darwinAuditRejected(darwinAuditRejectFilesystemAutomounted)
			}
			return darwinAuditRejected(darwinAuditRejectZeroInode)
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

// Call only after darwinAuditDirectorySecurity has rejected this observation.
func darwinAuditDirectoryRejection(state darwinAuditFileState, owner uint32, private bool) error {
	if state.mode&unix.S_IFMT != unix.S_IFDIR {
		return darwinAuditRejected(darwinAuditRejectDirectoryType)
	}
	if state.links == 0 {
		return darwinAuditRejected(darwinAuditRejectDirectoryLink)
	}
	if (state.uid != 0 && state.uid != owner) || (private && state.uid != owner) {
		return darwinAuditRejected(darwinAuditRejectDirectoryOwner)
	}
	if state.mode&(0022|unix.S_ISUID|unix.S_ISGID) != 0 || (private && state.mode&07777 != 0700) {
		return darwinAuditRejected(darwinAuditRejectDirectoryMode)
	}
	if private && state.flags != 0 {
		return darwinAuditRejected(darwinAuditRejectPrivateDirectoryFlags)
	}
	unsupported := state.flags & ^uint32(darwinAuditAncestorFlags)

	if unsupported != 0 {
		return darwinAuditRejected(darwinAuditRejectAncestorFlags)
	}
	if state.flags&unix.SF_FIRMLINK != 0 && state.uid != 0 {
		return darwinAuditRejected(darwinAuditRejectFirmlinkOwner)
	}
	return ErrJournalStorage
}

// Call only after the exact metadata equality comparison has failed.
func darwinAuditMetadataRejection(before, after darwinAuditFileState) error {
	if before.id != after.id {
		return darwinAuditRejected(darwinAuditRejectMetadataIdentity)
	}
	if before.filesystem != after.filesystem {
		return darwinAuditRejected(darwinAuditRejectMetadataFilesystem)
	}
	if before.size != after.size {
		return darwinAuditRejected(darwinAuditRejectMetadataSize)
	}
	if before.modified != after.modified || before.changed != after.changed {
		return darwinAuditRejected(darwinAuditRejectMetadataTimes)
	}
	if before.mode != after.mode || before.links != after.links || before.uid != after.uid || before.gid != after.gid || before.flags != after.flags || before.generation != after.generation {
		return darwinAuditRejected(darwinAuditRejectMetadataSecurity)
	}
	return darwinAuditRejected(darwinAuditRejectMetadataOther)
}

func darwinAuditInspectDirectory(file *os.File, owner uint32, private bool) (darwinAuditDirectoryState, error) {
	var zero darwinAuditDirectoryState
	before, err := darwinAuditMetadata(file)
	if err != nil || !darwinAuditDirectorySecurity(before, owner, private) {
		if err != nil {
			return zero, darwinAuditStorageRejection(err)
		}
		return zero, darwinAuditDirectoryRejection(before, owner, private)
	}
	if private {
		err = darwintrust.CheckEmptyACL(file)
	} else {
		err = darwintrust.CheckReadOnlyACL(file)
	}
	if err != nil {
		if private {
			return zero, darwinAuditRejected(darwinAuditRejectPrivateACL)
		}
		return zero, darwinAuditRejected(darwinAuditRejectAncestorACL)
	}
	after, err := darwinAuditMetadata(file)
	if err != nil || after != before {
		if err != nil {
			return zero, darwinAuditStorageRejection(err)
		}
		return zero, darwinAuditMetadataRejection(before, after)
	}
	return darwinAuditDirectoryState{id: after.id, filesystem: after.filesystem, mode: after.mode, uid: after.uid, gid: after.gid, flags: after.flags, generation: after.generation}, nil
}

func darwinAuditOpenAt(parent *os.File, name string, flags int, mode uint32) (file *os.File, failure error) {
	fd := -1
	failure = darwinAuditControl(parent, func(parentFD int) error {
		var err error
		fd, err = unix.Openat(parentFD, name, flags, mode)
		if err != nil {
			return darwinAuditRejected(darwinAuditRejectOpenat)
		}
		return nil
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
		if failure != nil {
			return nil, darwinAuditStorageRejection(failure)
		}
		return nil, darwinAuditRejected(darwinAuditRejectOpenRetain)
	}
	return file, nil
}

func darwinAuditNamedState(parent *os.File, name string) (state darwinAuditFileState, failure error) {
	failure = darwinAuditControl(parent, func(fd int) error {
		var stat unix.Stat_t
		if unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return darwinAuditRejected(darwinAuditRejectFstatat)
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
				var first *darwinAuditRejection
				if !errors.As(failure, &first) || first.rejectionCode() == "" {
					failure = darwinAuditStorageRejection(closeErr)
				}
			}
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, darwinAuditRejected(darwinAuditRejectRootOpen)
	}
	root := os.NewFile(uintptr(fd), "audit-fixed-root")
	if root == nil {
		_ = unix.Close(fd)
		return nil, darwinAuditRejected(darwinAuditRejectRootRetain)
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
			if err != nil {
				return nil, darwinAuditStorageRejection(err)
			}
			return nil, darwinAuditDirectoryRejection(before, d.owner, index+1 == len(parts))
		}
		child, err := darwinAuditOpenAt(binding.file, parts[index], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		// Keep ownership even when the next inspection fails.
		d.ancestors = append(d.ancestors, darwinAuditDirectoryBinding{file: child, parent: binding.file, name: parts[index]})
		opened, err := darwinAuditMetadata(child)
		if err != nil || opened.id != before.id {
			if err != nil {
				return nil, darwinAuditStorageRejection(err)
			}
			return nil, darwinAuditRejected(darwinAuditRejectOpenedIdentity)
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
			return nil, darwinAuditRejected(darwinAuditRejectParentBinding)
		}
		fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, darwinAuditRejected(darwinAuditRejectRootOpen)
		}
		file := os.NewFile(uintptr(fd), "audit-root-probe")
		if file == nil {
			_ = unix.Close(fd)
			return nil, darwinAuditRejected(darwinAuditRejectRootRetain)
		}
		return file, nil
	}
	before, err := darwinAuditNamedState(binding.parent, binding.name)
	if err != nil || !darwinAuditDirectorySecurity(before, d.owner, private) || before.id != binding.state.id {
		if err != nil {
			return nil, darwinAuditStorageRejection(err)
		}
		if !darwinAuditDirectorySecurity(before, d.owner, private) {
			return nil, darwinAuditDirectoryRejection(before, d.owner, private)
		}
		return nil, darwinAuditRejected(darwinAuditRejectOpenedIdentity)
	}
	return darwinAuditOpenAt(binding.parent, binding.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func (d *darwinAuditDirectory) checkBindingLocked() error {
	if d.closed || d.dir == nil || len(d.ancestors) == 0 || d.dir != d.ancestors[len(d.ancestors)-1].file {
		return darwinAuditRejected(darwinAuditRejectScopeState)
	}
	for index, binding := range d.ancestors {
		private := index == len(d.ancestors)-1
		if index == 0 && (binding.parent != nil || binding.name != "/") || index > 0 && binding.parent != d.ancestors[index-1].file {
			return darwinAuditRejected(darwinAuditRejectParentBinding)
		}
		state, err := darwinAuditInspectDirectory(binding.file, d.owner, private)
		if err != nil || state != binding.state {
			if err != nil {
				return darwinAuditStorageRejection(err)
			}
			return darwinAuditRejected(darwinAuditRejectSavedBinding)
		}
		probe, err := d.reopenBindingLocked(binding, private)
		if err != nil {
			return err
		}
		named, statErr := darwinAuditInspectDirectory(probe, d.owner, private)
		closeErr := probe.Close()
		if statErr != nil || closeErr != nil || named != binding.state {
			if statErr != nil {
				return darwinAuditStorageRejection(statErr)
			}
			if closeErr != nil {
				return darwinAuditRejected(darwinAuditRejectProbeClose)
			}
			return darwinAuditRejected(darwinAuditRejectReopenedState)
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
	} else if d.dir != nil {
		if err := d.checkBindingLocked(); err != nil {
			d.closeErr = darwinAuditStorageRejection(err)
		}
	}
	d.closed = true
	for index := len(d.ancestors) - 1; index >= 0; index-- {
		if d.ancestors[index].file != nil && d.ancestors[index].file.Close() != nil && d.closeErr == nil {
			d.closeErr = darwinAuditRejected(darwinAuditRejectOwnedClose)
		}
	}
	d.dir = nil
	if d.checkPrincipalLocked() != nil {
		d.closeErr = ErrProcessIdentity
	}
	return d.closeErr
}
