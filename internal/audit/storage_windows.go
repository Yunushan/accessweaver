//go:build windows && (amd64 || arm64)

package audit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsAuditIdentity struct {
	volume uint64
	fileID [16]byte
}

type windowsAuditFileState struct {
	id         windowsAuditIdentity
	size       int64
	writeTime  windows.Filetime
	attributes uint32
	links      uint32
}

type windowsAuditDirectoryBinding struct {
	handle    windows.Handle
	component string // Empty only for the drive-root binding.
	id        windowsAuditIdentity
}

// windowsAuditDirectory owns every handle from the drive root to the private
// final directory. None permits delete sharing. Child I/O uses single native
// components relative to the retained final handle, never a rebuilt full path.
// The executing account and privileged OS administrators remain trusted.
// Native I/O is synchronous and has no deadline; no worker outlives a method.
// This boundary does not itself establish initialization/write durability.
type windowsAuditDirectory struct {
	mu        sync.Mutex
	handle    windows.Handle
	path      string
	owner     string
	principal processPrincipal
	ancestors []windowsAuditDirectoryBinding
	closed    bool
	closeErr  error
}

// parseWindowsAuditPath is deliberately narrower than the Win32 namespace. The
// returned components are suitable only for individual RootDirectory opens.
func parseWindowsAuditPath(path string) (string, []string, error) {
	if !utf8.ValidString(path) || len(path) < 3 || len(path) > 32760 ||
		!((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) ||
		path[1] != ':' || path[2] != '\\' || strings.ContainsAny(path, "/\x00\r\n") ||
		filepath.Clean(path) != path {
		return "", nil, ErrJournalStorage
	}
	root := path[:3]
	if len(path) == 3 {
		return root, nil, nil
	}
	parts := strings.Split(path[3:], `\`)
	for _, part := range parts {
		if !validWindowsAuditComponent(part) {
			return "", nil, ErrJournalStorage
		}
	}
	return root, parts, nil
}

func validWindowsAuditComponent(part string) bool {
	if part == "" || part == "." || part == ".." || !utf8.ValidString(part) ||
		strings.ContainsAny(part, `\/:*?"<>|`) || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
		return false
	}
	for _, ch := range part {
		if ch < 32 {
			return false
		}
	}
	encoded, err := windows.UTF16FromString(part)
	if err != nil || len(encoded)-1 > 255 {
		return false
	}
	base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return false
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		suffix := strings.TrimPrefix(strings.TrimPrefix(base, "COM"), "LPT")
		if suffix == "1" || suffix == "2" || suffix == "3" || suffix == "4" || suffix == "5" ||
			suffix == "6" || suffix == "7" || suffix == "8" || suffix == "9" || suffix == "¹" || suffix == "²" || suffix == "³" {
			return false
		}
	}
	return true
}

func windowsAuditChild(name string) bool {
	return name == actorKeyName || name == journalName
}

func windowsAuditStorageError(err error) error {
	var status windows.NTStatus
	if errors.As(err, &status) {
		err = status.Errno()
	}
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrJournalBusy
	}
	return ErrJournalStorage
}

func windowsAuditMissing(err error) bool {
	var status windows.NTStatus
	if errors.As(err, &status) {
		err = status.Errno()
	}
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}

// nativeWindowsAuditOpen is called only while pinned to a verified process-token
// thread. A zero parent is allowed only for the already parsed native drive root.
func nativeWindowsAuditOpen(parent windows.Handle, name string, access, disposition, options uint32, descriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, ErrJournalStorage
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		RootDirectory: parent, ObjectName: objectName,
		Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: descriptor,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var result windows.Handle = windows.InvalidHandle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&result, access, &attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition,
		options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	runtime.KeepAlive(objectName)
	runtime.KeepAlive(descriptor)
	if err != nil {
		if result != 0 && result != windows.InvalidHandle {
			_ = windows.CloseHandle(result)
		}
		return windows.InvalidHandle, err
	}
	if result == 0 || result == windows.InvalidHandle || status.Status != 0 ||
		(disposition == windows.FILE_CREATE && status.Information != 2) ||
		(disposition == windows.FILE_OPEN && status.Information != 1) {
		if result != 0 && result != windows.InvalidHandle {
			_ = windows.CloseHandle(result)
		}
		return windows.InvalidHandle, ErrJournalStorage
	}
	return result, nil
}

const windowsAuditMetadataAccess = windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE
const windowsAuditDirectoryAccess = windowsAuditMetadataAccess | windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE

func windowsAuditVolume(handle windows.Handle) error {
	var flags uint32
	var fs [32]uint16
	if windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &flags, &fs[0], uint32(len(fs))) != nil ||
		windows.UTF16ToString(fs[:]) != "NTFS" || flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return ErrJournalStorage
	}
	return nil
}

func windowsAuditHandleState(handle windows.Handle, directory bool) (windowsAuditFileState, error) {
	var result windowsAuditFileState
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK || windowsAuditVolume(handle) != nil {
		return result, ErrJournalStorage
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil {
		return result, ErrJournalStorage
	}
	// Refuse indirect, recallable, transient and special storage. Ordinary
	// hidden/system/archive/indexing flags do not alter regular-file semantics.
	const allowed = windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM |
		windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	if info.FileAttributes & ^uint32(allowed) != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || info.NumberOfLinks == 0 {
		return result, ErrJournalStorage
	}
	var identity struct {
		Volume uint64
		ID     [16]byte
	}
	if windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&identity)), uint32(unsafe.Sizeof(identity))) != nil || identity.ID == ([16]byte{}) {
		return result, ErrJournalStorage
	}
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if size > uint64(^uint64(0)>>1) {
		return result, ErrJournalStorage
	}
	return windowsAuditFileState{
		id: windowsAuditIdentity{identity.Volume, identity.ID}, size: int64(size),
		writeTime: info.LastWriteTime, attributes: info.FileAttributes, links: info.NumberOfLinks,
	}, nil
}

func openWindowsAuditDirectory(path string) (result *windowsAuditDirectory, failure error) {
	root, parts, err := parseWindowsAuditPath(path)
	if err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	principal, err := currentProcessPrincipal()
	if err != nil || principal.kind != "sid" {
		return nil, ErrProcessIdentity
	}
	d := &windowsAuditDirectory{path: path, owner: principal.value, principal: principal}
	defer func() {
		if d.checkPrincipalLocked() != nil {
			result, failure = nil, ErrProcessIdentity
		}
		if result == nil {
			_ = d.Close()
		}
	}()
	rootName, err := windows.UTF16PtrFromString(root)
	if err != nil || windows.GetDriveType(rootName) != windows.DRIVE_FIXED {
		return nil, ErrJournalStorage
	}
	rootHandle, err := nativeWindowsAuditOpen(0, `\??\`+root, windowsAuditDirectoryAccess, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
	if err != nil {
		return nil, windowsAuditStorageError(err)
	}
	d.ancestors = append(d.ancestors, windowsAuditDirectoryBinding{handle: rootHandle})
	for index := 0; index <= len(parts); index++ {
		binding := &d.ancestors[index]
		state, err := windowsAuditHandleState(binding.handle, true)
		if err != nil || checkWindowsAuditSecurity(binding.handle, d.owner, index == len(parts)) != nil {
			return nil, ErrJournalStorage
		}
		if index > 0 && state.id.volume != d.ancestors[0].id.volume {
			return nil, ErrJournalStorage
		}
		binding.id = state.id
		if index == len(parts) {
			d.handle = binding.handle
			break
		}
		handle, err := nativeWindowsAuditOpen(binding.handle, parts[index], windowsAuditDirectoryAccess, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
		if err != nil {
			return nil, windowsAuditStorageError(err)
		}
		d.ancestors = append(d.ancestors, windowsAuditDirectoryBinding{handle: handle, component: parts[index]})
	}
	if d.checkBindingLocked() != nil {
		return nil, ErrJournalStorage
	}
	if d.checkPrincipalLocked() != nil {
		return nil, ErrProcessIdentity
	}
	return d, nil
}

func (d *windowsAuditDirectory) checkPrincipalLocked() error {
	principal, err := currentProcessPrincipal()
	if err != nil || principal != d.principal || principal.value != d.owner {
		return ErrProcessIdentity
	}
	return nil
}

func (d *windowsAuditDirectory) checkBindingLocked() error {
	if d.closed || d.handle == 0 || d.handle == windows.InvalidHandle || len(d.ancestors) == 0 || len(d.path) < 3 {
		return ErrJournalStorage
	}
	root := d.path[:3]
	rootName, err := windows.UTF16PtrFromString(root)
	if err != nil || windows.GetDriveType(rootName) != windows.DRIVE_FIXED {
		return ErrJournalStorage
	}
	for index, binding := range d.ancestors {
		state, err := windowsAuditHandleState(binding.handle, true)
		if err != nil || state.id != binding.id || checkWindowsAuditSecurity(binding.handle, d.owner, index == len(d.ancestors)-1) != nil {
			return ErrJournalStorage
		}
		parent, name := windows.Handle(0), `\??\`+root
		if index > 0 {
			parent, name = d.ancestors[index-1].handle, binding.component
		}
		probe, err := nativeWindowsAuditOpen(parent, name, windowsAuditMetadataAccess|windows.FILE_TRAVERSE, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
		if err != nil {
			return windowsAuditStorageError(err)
		}
		current, statErr := windowsAuditHandleState(probe, true)
		securityErr := checkWindowsAuditSecurity(probe, d.owner, index == len(d.ancestors)-1)
		closeErr := windows.CloseHandle(probe)
		if statErr != nil || securityErr != nil || closeErr != nil || current.id != binding.id {
			return ErrJournalStorage
		}
	}
	if d.handle != d.ancestors[len(d.ancestors)-1].handle {
		return ErrJournalStorage
	}
	return nil
}

func (d *windowsAuditDirectory) checkBinding() error {
	if d == nil {
		return ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if d.checkPrincipalLocked() != nil {
		return ErrProcessIdentity
	}
	err := d.checkBindingLocked()
	if d.checkPrincipalLocked() != nil {
		return ErrProcessIdentity
	}
	return err
}

func (d *windowsAuditDirectory) createRegular(name string) (*os.File, error) {
	return d.openRegularUsing(name, true, true)
}

func (d *windowsAuditDirectory) openRegular(name string, writable bool) (*os.File, error) {
	return d.openRegularUsing(name, writable, false)
}

func (d *windowsAuditDirectory) openRegularUsing(name string, writable, create bool) (result *os.File, failure error) {
	if d == nil || !windowsAuditChild(name) {
		return nil, ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() {
		if d.checkPrincipalLocked() != nil {
			if result != nil {
				_ = result.Close()
			}
			result, failure = nil, ErrProcessIdentity
		}
	}()
	if d.checkPrincipalLocked() != nil {
		return nil, ErrProcessIdentity
	}
	if err := d.checkBindingLocked(); err != nil {
		return nil, err
	}
	access := uint32(windows.FILE_READ_DATA | windowsAuditMetadataAccess)
	options := uint32(windows.FILE_NON_DIRECTORY_FILE)
	if writable {
		access |= windows.FILE_GENERIC_WRITE
		options |= windows.FILE_WRITE_THROUGH
	}
	disposition := uint32(windows.FILE_OPEN)
	var descriptor *windows.SECURITY_DESCRIPTOR
	if create {
		var err error
		descriptor, err = windowsAuditSecurityDescriptor(d.owner, false)
		if err != nil {
			return nil, ErrJournalStorage
		}
		disposition = windows.FILE_CREATE
	}
	handle, err := nativeWindowsAuditOpen(d.handle, name, access, disposition, options, descriptor)
	if err != nil {
		return nil, windowsAuditStorageError(err)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrJournalStorage
	}
	defer func() {
		if result == nil {
			_ = file.Close()
		}
	}()
	if _, err := d.fileStateLocked(file, name); err != nil {
		return nil, err
	}
	if d.checkPrincipalLocked() != nil {
		return nil, ErrProcessIdentity
	}
	return file, nil
}

func (d *windowsAuditDirectory) fileStateLocked(file *os.File, name string) (windowsAuditFileState, error) {
	var zero windowsAuditFileState
	if file == nil || !windowsAuditChild(name) {
		return zero, ErrJournalStorage
	}
	defer runtime.KeepAlive(file)
	if err := d.checkBindingLocked(); err != nil {
		return zero, err
	}
	handle := windows.Handle(file.Fd())
	state, err := windowsAuditHandleState(handle, false)
	if err != nil || state.links != 1 || state.id.volume != d.ancestors[0].id.volume || checkWindowsAuditSecurity(handle, d.owner, true) != nil {
		return zero, ErrJournalStorage
	}
	limit := int64(MaxJournalBytes)
	if name == actorKeyName {
		limit = int64(actorKeyFileBytes)
	}
	if state.size < 0 || state.size > limit {
		return zero, ErrJournalStorage
	}
	probe, err := nativeWindowsAuditOpen(d.handle, name, windowsAuditMetadataAccess, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	if err != nil {
		return zero, windowsAuditStorageError(err)
	}
	named, statErr := windowsAuditHandleState(probe, false)
	securityErr := checkWindowsAuditSecurity(probe, d.owner, true)
	closeErr := windows.CloseHandle(probe)
	if statErr != nil || securityErr != nil || closeErr != nil || named != state {
		return zero, ErrJournalStorage
	}
	runtime.KeepAlive(file)
	return state, nil
}

func (d *windowsAuditDirectory) fileState(file *os.File, name string) (windowsAuditFileState, error) {
	var zero windowsAuditFileState
	if d == nil {
		return zero, ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if d.checkPrincipalLocked() != nil {
		return zero, ErrProcessIdentity
	}
	state, err := d.fileStateLocked(file, name)
	if d.checkPrincipalLocked() != nil {
		return zero, ErrProcessIdentity
	}
	return state, err
}

// probeIdentity opens metadata only. Historical export neither requires a key
// nor inspects its contents/security descriptor. Reparse/special storage never
// gets followed or opened as a data stream, even when it occupies the key name.
func (d *windowsAuditDirectory) probeIdentity(name string) (identity windowsAuditIdentity, present bool, failure error) {
	var zero windowsAuditIdentity
	if d == nil || !windowsAuditChild(name) {
		return zero, false, ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer func() {
		if d.checkPrincipalLocked() != nil {
			identity, present, failure = zero, false, ErrProcessIdentity
		}
	}()
	if d.checkPrincipalLocked() != nil {
		return zero, false, ErrProcessIdentity
	}
	if err := d.checkBindingLocked(); err != nil {
		return zero, false, err
	}
	// READ_CONTROL is intentionally absent: the archive's old key ACL is not
	// an export prerequisite. FILE_READ_DATA is never requested for this probe.
	handle, err := nativeWindowsAuditOpen(d.handle, name, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	if err != nil {
		if d.checkPrincipalLocked() != nil {
			return zero, false, ErrProcessIdentity
		}
		if windowsAuditMissing(err) {
			return zero, false, nil
		}
		return zero, false, windowsAuditStorageError(err)
	}
	state, statErr := windowsAuditHandleState(handle, false)
	closeErr := windows.CloseHandle(handle)
	if d.checkPrincipalLocked() != nil {
		return zero, false, ErrProcessIdentity
	}
	if statErr != nil || closeErr != nil || state.id.volume != d.ancestors[0].id.volume {
		return zero, false, ErrJournalStorage
	}
	return state.id, true, nil
}

// requireEmpty reads an independent directory file object. Duplicating the
// retained handle would share its enumeration cursor; reopening its bound final
// component relative to its retained parent does not. The identity must match.
func (d *windowsAuditDirectory) requireEmpty() (failure error) {
	if d == nil {
		return ErrJournalStorage
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if d.checkPrincipalLocked() != nil {
		return ErrProcessIdentity
	}
	defer func() {
		if err := d.checkBindingLocked(); err != nil && failure == nil {
			failure = err
		}
		if d.checkPrincipalLocked() != nil {
			failure = ErrProcessIdentity
		}
	}()
	if err := d.checkBindingLocked(); err != nil {
		return err
	}
	last := len(d.ancestors) - 1
	parent, name := windows.Handle(0), `\??\`+d.path[:3]
	if last > 0 {
		parent, name = d.ancestors[last-1].handle, d.ancestors[last].component
	}
	handle, err := nativeWindowsAuditOpen(parent, name, windowsAuditDirectoryAccess, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
	if err != nil {
		return windowsAuditStorageError(err)
	}
	file := os.NewFile(uintptr(handle), "audit-directory-enumeration")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return ErrJournalStorage
	}
	defer func() {
		if file.Close() != nil && failure == nil {
			failure = ErrJournalStorage
		}
	}()
	state, err := windowsAuditHandleState(handle, true)
	if err != nil || state.id != d.ancestors[len(d.ancestors)-1].id || checkWindowsAuditSecurity(handle, d.owner, true) != nil {
		return ErrJournalStorage
	}
	// Go 1.26 enumerates this native directory handle with
	// GetFileInformationByHandleEx. Readdirnames does not open child entries.
	names, readErr := file.Readdirnames(1)
	if len(names) != 0 || !errors.Is(readErr, io.EOF) {
		return ErrJournalStorage
	}
	after, err := windowsAuditHandleState(handle, true)
	if err != nil || after.id != state.id || checkWindowsAuditSecurity(handle, d.owner, true) != nil {
		return ErrJournalStorage
	}
	return nil
}

// windowsAuditOutputIdentity compares an already opened output object without
// reading its data or requiring private source-storage permissions. Pipes and
// consoles return regular=false. A disk file whose identity cannot be obtained
// safely refuses instead of weakening alias protection. Control retains the
// descriptor while its metadata is queried; the caller supplies output access.
func windowsAuditOutputIdentity(file *os.File) (identity windowsAuditIdentity, regular bool, failure error) {
	if file == nil {
		return windowsAuditIdentity{}, false, ErrExportOutput
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	principal, err := currentProcessPrincipal()
	if err != nil {
		return windowsAuditIdentity{}, false, ErrProcessIdentity
	}
	defer func() {
		after, err := currentProcessPrincipal()
		if err != nil || after != principal {
			identity, regular, failure = windowsAuditIdentity{}, false, ErrProcessIdentity
		}
		runtime.KeepAlive(file)
	}()
	connection, err := file.SyscallConn()
	if err != nil {
		return windowsAuditIdentity{}, false, ErrExportOutput
	}
	var queryErr error
	err = connection.Control(func(raw uintptr) {
		handle := windows.Handle(raw)
		kind, err := windows.GetFileType(handle)
		if err != nil {
			queryErr = ErrExportOutput
			return
		}
		if kind == windows.FILE_TYPE_PIPE || kind == windows.FILE_TYPE_CHAR {
			return
		}
		if kind != windows.FILE_TYPE_DISK {
			queryErr = ErrExportOutput
			return
		}
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &info) != nil ||
			info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
			queryErr = ErrExportOutput
			return
		}
		var native struct {
			Volume uint64
			ID     [16]byte
		}
		if windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&native)), uint32(unsafe.Sizeof(native))) != nil || native.ID == ([16]byte{}) {
			queryErr = ErrExportOutput
			return
		}
		identity, regular = windowsAuditIdentity{native.Volume, native.ID}, true
	})
	if err != nil || queryErr != nil {
		return windowsAuditIdentity{}, false, ErrExportOutput
	}
	return identity, regular, nil
}

// Close always attempts every owned close, including under an impersonated
// thread. It never deletes storage and preserves the first close result.
func (d *windowsAuditDirectory) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return d.closeErr
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	d.closed = true
	if len(d.ancestors) != 0 && d.checkPrincipalLocked() != nil {
		d.closeErr = ErrProcessIdentity
	}
	for index := len(d.ancestors) - 1; index >= 0; index-- {
		handle := d.ancestors[index].handle
		if handle != 0 && handle != windows.InvalidHandle && windows.CloseHandle(handle) != nil {
			if d.closeErr == nil {
				d.closeErr = ErrJournalStorage
			}
		}
	}
	d.handle = 0
	if len(d.ancestors) != 0 && d.checkPrincipalLocked() != nil && d.closeErr == nil {
		d.closeErr = ErrProcessIdentity
	}
	return d.closeErr
}
