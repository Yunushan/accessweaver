//go:build windows

package fileidentity

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Every filesystem call runs on one pinned thread, with the process SID and
// elevation checked on both sides. An impersonation token always refuses,
// including identification-only tokens. The helper never changes a token.
type windowsPrincipal struct {
	sid      string
	elevated uint32
}

type windowsContext struct{ principal windowsPrincipal }

func processThreadContext() error {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err == nil {
		_ = token.Close()
		return ErrUnavailable
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return ErrUnavailable
	}
	return nil
}

func principalSnapshot() (result windowsPrincipal, failure error) {
	if processThreadContext() != nil {
		return result, ErrUnavailable
	}
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return result, ErrUnavailable
	}
	defer func() {
		// Closing an owned token is attempted even if a context check fails.
		before := processThreadContext()
		closed := token.Close()
		after := processThreadContext()
		if before != nil || closed != nil || after != nil {
			result, failure = windowsPrincipal{}, ErrUnavailable
		}
	}()
	if processThreadContext() != nil {
		return result, ErrUnavailable
	}
	user, err := token.GetTokenUser()
	if processThreadContext() != nil || err != nil || user == nil || user.User.Sid == nil {
		return result, ErrUnavailable
	}
	if processThreadContext() != nil {
		return result, ErrUnavailable
	}
	valid := user.User.Sid.IsValid()
	if processThreadContext() != nil || !valid {
		return result, ErrUnavailable
	}
	if processThreadContext() != nil {
		return result, ErrUnavailable
	}
	sid := user.User.Sid.String()
	if processThreadContext() != nil || sid == "" {
		return result, ErrUnavailable
	}
	var elevated, size uint32
	if processThreadContext() != nil {
		return result, ErrUnavailable
	}
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &size)
	if processThreadContext() != nil || err != nil || size != uint32(unsafe.Sizeof(elevated)) || elevated > 1 {
		return result, ErrUnavailable
	}
	return windowsPrincipal{sid, elevated}, nil
}

func (context windowsContext) check() error {
	current, err := principalSnapshot()
	if err != nil || current != context.principal {
		return ErrUnavailable
	}
	return nil
}

func (context windowsContext) call(operation func() error) error {
	if context.check() != nil {
		return ErrUnavailable
	}
	err := operation()
	if context.check() != nil {
		return ErrUnavailable
	}
	return err
}

// Owned descriptors must be closed even after context validation fails.
func (context windowsContext) close(handle windows.Handle) error {
	before := context.check()
	closed := windows.CloseHandle(handle)
	after := context.check()
	if before != nil || closed != nil || after != nil {
		return ErrUnavailable
	}
	return nil
}

func fromFile(file *os.File) (result State, failure error) {
	if file == nil {
		return State{}, ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer runtime.KeepAlive(file)
	principal, err := principalSnapshot()
	if err != nil {
		return State{}, ErrUnavailable
	}
	context := windowsContext{principal}
	defer func() {
		if context.check() != nil {
			result, failure = State{}, ErrUnavailable
		}
	}()
	connection, err := file.SyscallConn()
	if err != nil {
		return State{}, ErrUnavailable
	}
	var queryErr error
	err = connection.Control(func(raw uintptr) { result, queryErr = context.state(windows.Handle(raw)) })
	if err != nil || queryErr != nil {
		return State{}, ErrUnavailable
	}
	return result, nil
}

// FILE_ID_INFO preserves the complete native identity on both Windows targets.
type windowsIDInfo struct {
	Volume uint64
	FileID [16]byte
}

func (context windowsContext) state(handle windows.Handle) (State, error) {
	var kind uint32
	if context.call(func() (err error) { kind, err = windows.GetFileType(handle); return err }) != nil {
		return State{}, ErrUnavailable
	}
	if kind == windows.FILE_TYPE_PIPE || kind == windows.FILE_TYPE_CHAR {
		return State{Kind: Other}, nil
	}
	if kind != windows.FILE_TYPE_DISK || context.localDisk(handle) != nil {
		return State{}, ErrUnavailable
	}
	// This metadata API supports ordinary write-only and append-only output
	// handles. FileBasicInfo may require READ_ATTRIBUTES those handles lack.
	// Its legacy file-index fields are deliberately never used for identity.
	var metadata windows.ByHandleFileInformation
	if context.call(func() error { return windows.GetFileInformationByHandle(handle, &metadata) }) != nil ||
		metadata.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 {
		return State{}, ErrUnavailable
	}
	size := uint64(metadata.FileSizeHigh)<<32 | uint64(metadata.FileSizeLow)
	writeTime := uint64(metadata.LastWriteTime.HighDateTime)<<32 | uint64(metadata.LastWriteTime.LowDateTime)
	if size > uint64(1<<63-1) || writeTime > uint64(1<<63-1) {
		return State{}, ErrUnavailable
	}
	var identity windowsIDInfo
	if context.call(func() error {
		return windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&identity)), uint32(unsafe.Sizeof(identity)))
	}) != nil || identity.FileID == ([16]byte{}) {
		return State{}, ErrUnavailable
	}
	result := State{ID: ID{identity.Volume, identity.FileID}, Kind: Regular, Size: int64(size),
		Modified: time.Unix(int64(writeTime/10000000)-11644473600, int64(writeTime%10000000)*100).UTC()}
	if metadata.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		result.Kind = Reparse
	} else if metadata.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		result.Kind = Directory
	}
	return result, nil
}

func localNativeDiskPath(path string) bool {
	const prefix = `\Device\HarddiskVolume`
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	remainder := strings.TrimPrefix(path, prefix)
	end := strings.IndexByte(remainder, '\\')
	if end < 0 {
		end = len(remainder)
	}
	if end < 1 {
		return false
	}
	for _, ch := range remainder[:end] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (context windowsContext) localDisk(handle windows.Handle) error {
	// Win32 owns synchronous completion even for a borrowed OVERLAPPED
	// handle. FILE_NAME_OPENED avoids normalized-name traversal and extra
	// directory permissions. VOLUME_NAME_NT exposes the bound device; remote
	// redirectors and arbitrary devices cannot satisfy this local-disk form.
	const volumeNameNT, fileNameOpened = 0x2, 0x8
	var path [windowsPathLimit]uint16
	var length uint32
	if context.call(func() (err error) {
		length, err = windows.GetFinalPathNameByHandle(handle, &path[0], uint32(len(path)), volumeNameNT|fileNameOpened)
		return err
	}) != nil || length == 0 || length >= uint32(len(path)) || !localNativeDiskPath(windows.UTF16ToString(path[:length])) {
		return ErrUnavailable
	}
	return nil
}

const windowsPathLimit = 32760
const windowsResolutionBudget = 65520
const windowsComponentLimit = 2048

// These are ordinary DOS paths only. UNC, device and extended namespaces never
// reach a native open, even when filepath.Abs could turn one into another form.
func ordinaryWindowsPath(path string) bool {
	if path == "" || !utf8.ValidString(path) || len(path) > windowsPathLimit || strings.ContainsRune(path, 0) {
		return false
	}
	path = strings.ReplaceAll(path, "/", `\`)
	lower := strings.ToLower(path)
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(lower, `\??\`) || strings.HasPrefix(lower, `\device\`) ||
		strings.HasPrefix(lower, `\global??\`) || strings.HasPrefix(lower, `\dosdevices\`) {
		return false
	}
	return true
}

func windowsDrivePath(path string) (string, []string, error) {
	path = strings.ReplaceAll(path, "/", `\`)
	if !ordinaryWindowsPath(path) || len(path) < 3 || path[1] != ':' || path[2] != '\\' ||
		!((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
		return "", nil, ErrUnavailable
	}
	if len(path) == 3 {
		return path, nil, nil
	}
	parts := strings.Split(strings.TrimSuffix(path[3:], `\`), `\`)
	if len(parts) > windowsComponentLimit {
		return "", nil, ErrUnavailable
	}
	for index, part := range parts {
		component, err := windowsComponent(part, index == len(parts)-1)
		if err != nil {
			return "", nil, ErrUnavailable
		}
		parts[index] = component
	}
	return path[:3], parts, nil
}

func windowsComponent(part string, allowStream bool) (string, error) {
	if part == "" || !utf8.ValidString(part) || strings.ContainsAny(part, `\/"<>|?*`) {
		return "", ErrUnavailable
	}
	for _, ch := range part {
		if ch < 32 {
			return "", ErrUnavailable
		}
	}
	streams := strings.Split(part, ":")
	if len(streams) > 3 || len(streams) > 1 && !allowStream {
		return "", ErrUnavailable
	}
	base := strings.TrimRight(streams[0], " .")
	if base == "" {
		return "", ErrUnavailable
	}
	stem := strings.ToUpper(strings.TrimRight(strings.SplitN(base, ".", 2)[0], " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return "", ErrUnavailable
	}
	if len(stem) > 3 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) {
		switch stem[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return "", ErrUnavailable
		}
	}
	if len(streams) > 1 {
		if len(streams) == 2 && streams[1] == "" || len(streams) == 3 && !strings.EqualFold(streams[2], "$DATA") {
			return "", ErrUnavailable
		}
		part = base + ":" + streams[1]
		if len(streams) == 3 {
			part += ":$DATA"
		}
	} else {
		part = base
	}
	encoded, err := windows.UTF16FromString(part)
	if err != nil || len(encoded)-1 > 255 {
		return "", ErrUnavailable
	}
	return part, nil
}

func nativeMissing(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_NO_SUCH_FILE) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func (context windowsContext) open(parent windows.Handle, name string) (windows.Handle, error) {
	return context.openAccess(parent, name, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE)
}

func (context windowsContext) openAccess(parent windows.Handle, name string, access uint32) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, ErrUnavailable
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var handle windows.Handle = windows.InvalidHandle
	var status windows.IO_STATUS_BLOCK
	// FILE_DIRECTORY_FILE is incompatible with FILE_OPEN_NO_RECALL. Open
	// metadata without a type restriction, then check the returned handle
	// before using a root or intermediate component as a directory.
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_NO_RECALL)
	err = context.call(func() error {
		return windows.NtCreateFile(&handle, access, &attributes, &status, nil, 0,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, options, 0, 0)
	})
	runtime.KeepAlive(objectName)
	if err != nil || handle == 0 || handle == windows.InvalidHandle || status.Status != 0 || status.Information != 1 {
		if handle != 0 && handle != windows.InvalidHandle {
			if context.close(handle) != nil {
				return windows.InvalidHandle, ErrUnavailable
			}
		}
		if nativeMissing(err) {
			return windows.InvalidHandle, os.ErrNotExist
		}
		return windows.InvalidHandle, ErrUnavailable
	}
	return handle, nil
}

func fromPath(path string, followLinks bool) (State, error) {
	return inspectWindowsPath(path, followLinks, nil)
}

// consume runs while all metadata owners and the final parent are still held.
// It must not borrow an owner beyond the call. A separate data handle can be
// acquired relative to that parent and checked against the inspected identity.
func inspectWindowsPath(path string, followLinks bool, consume func(windowsContext, windows.Handle, string, State) error) (result State, failure error) {
	if !ordinaryWindowsPath(path) {
		return State{}, ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	principal, err := principalSnapshot()
	if err != nil {
		return State{}, ErrUnavailable
	}
	context := windowsContext{principal}
	var owned []windows.Handle
	defer func() {
		for index := len(owned) - 1; index >= 0; index-- {
			if context.close(owned[index]) != nil {
				result, failure = State{}, ErrUnavailable
			}
		}
		if context.check() != nil {
			result, failure = State{}, ErrUnavailable
		}
	}()
	var absolute string
	if context.call(func() (err error) { absolute, err = filepath.Abs(path); return err }) != nil {
		return State{}, ErrUnavailable
	}
	root, pending, err := windowsDrivePath(absolute)
	if err != nil {
		return State{}, ErrUnavailable
	}
	// Query the DOS mapping first, then open the generated native disk root.
	// Opening the DOS spelling itself would permit a mapping race to redirect
	// the probe to a remote filesystem or a device before it could be checked.
	hops, budget, operations := 0, len(absolute), 0
	openRoot := func(root string) (windows.Handle, []string, error) {
		var prefix []string
		for aliases := 0; aliases < 40; aliases++ {
			encoded, err := windows.UTF16PtrFromString(root[:2])
			if err != nil {
				return windows.InvalidHandle, nil, ErrUnavailable
			}
			var mapping [windowsPathLimit]uint16
			var length uint32
			if context.call(func() (err error) {
				length, err = windows.QueryDosDevice(encoded, &mapping[0], uint32(len(mapping)))
				return err
			}) != nil || length == 0 || length > uint32(len(mapping)) {
				return windows.InvalidHandle, nil, ErrUnavailable
			}
			end := 0
			for end < int(length) && mapping[end] != 0 {
				end++
			}
			if end == 0 || end == int(length) {
				return windows.InvalidHandle, nil, ErrUnavailable
			}
			target := windows.UTF16ToString(mapping[:end])
			budget += len(target)
			if budget > windowsResolutionBudget {
				return windows.InvalidHandle, nil, ErrUnavailable
			}
			if localNativeDiskPath(target+`\`) && !strings.Contains(strings.TrimPrefix(target, `\Device\HarddiskVolume`), `\`) {
				handle, err := context.open(0, target+`\`)
				if err != nil {
					return windows.InvalidHandle, nil, err
				}
				owned = append(owned, handle)
				state, err := context.state(handle)
				if err != nil || state.Kind != Directory {
					return windows.InvalidHandle, nil, ErrUnavailable
				}
				return handle, prefix, nil
			}
			// SUBST-style drive aliases may name another ordinary local drive.
			// No other object-manager spelling, remote or native target follows.
			if !strings.HasPrefix(target, `\??\`) {
				return windows.InvalidHandle, nil, ErrUnavailable
			}
			nextRoot, components, err := windowsDrivePath(strings.TrimPrefix(target, `\??\`))
			if err != nil {
				return windows.InvalidHandle, nil, ErrUnavailable
			}
			for _, component := range components {
				if strings.Contains(component, ":") {
					return windows.InvalidHandle, nil, ErrUnavailable
				}
			}
			prefix = append(components, prefix...)
			if len(prefix) > windowsComponentLimit {
				return windows.InvalidHandle, nil, ErrUnavailable
			}
			root = nextRoot
		}
		return windows.InvalidHandle, nil, ErrUnavailable
	}
	handle, prefix, err := openRoot(root)
	if err != nil {
		return State{}, err
	}
	if len(prefix) != 0 && len(pending) == 0 {
		pending = []string{"."}
	}
	pending = append(prefix, pending...)
	stack := []windows.Handle{handle}
	for len(pending) != 0 {
		operations++
		if operations > windowsComponentLimit || budget > windowsResolutionBudget {
			return State{}, ErrUnavailable
		}
		part := pending[0]
		pending = pending[1:]
		if part == "." {
			continue
		}
		if part == ".." {
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		component, err := windowsComponent(part, len(pending) == 0)
		if err != nil {
			return State{}, ErrUnavailable
		}
		handle, err := context.open(stack[len(stack)-1], component)
		if err != nil {
			return State{}, err
		}
		owned = append(owned, handle)
		state, err := context.state(handle)
		if err != nil {
			return State{}, ErrUnavailable
		}
		if state.Kind == Reparse && (followLinks || len(pending) != 0) {
			hops++
			if hops > 40 {
				return State{}, ErrUnavailable
			}
			target, relative, err := context.reparseTarget(handle)
			if err != nil {
				return State{}, ErrUnavailable
			}
			budget += len(target)
			if budget > windowsResolutionBudget {
				return State{}, ErrUnavailable
			}
			if relative {
				if !ordinaryWindowsPath(target) || strings.HasPrefix(target, `\`) || strings.Contains(target, ":") {
					return State{}, ErrUnavailable
				}
				pending = append(strings.Split(strings.ReplaceAll(target, "/", `\`), `\`), pending...)
			} else {
				// Only an explicitly local drive substitution is admitted. UNC,
				// native device, volume-GUID and object-manager aliases refuse.
				if !strings.HasPrefix(target, `\??\`) {
					return State{}, ErrUnavailable
				}
				targetRoot, targetParts, err := windowsDrivePath(strings.TrimPrefix(target, `\??\`))
				if err != nil {
					return State{}, ErrUnavailable
				}
				newRoot, prefix, err := openRoot(targetRoot)
				if err != nil {
					return State{}, err
				}
				stack = []windows.Handle{newRoot}
				pending = append(targetParts, pending...)
				if len(prefix) != 0 && len(pending) == 0 {
					pending = []string{"."}
				}
				pending = append(prefix, pending...)
			}
			continue
		}
		if len(pending) == 0 {
			if consume != nil {
				if err := consume(context, stack[len(stack)-1], component, state); err != nil {
					return State{}, err
				}
			}
			return state, nil
		}
		if state.Kind != Directory {
			return State{}, ErrUnavailable
		}
		stack = append(stack, handle)
	}
	return context.state(stack[len(stack)-1])
}

func (context windowsContext) reparseTarget(handle windows.Handle) (string, bool, error) {
	var data [windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE]byte
	var returned uint32
	if context.call(func() error {
		return windows.DeviceIoControl(handle, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &data[0], uint32(len(data)), &returned, nil)
	}) != nil || returned < 8 || returned > uint32(len(data)) {
		return "", false, ErrUnavailable
	}
	tag := binary.LittleEndian.Uint32(data[:4])
	length := int(binary.LittleEndian.Uint16(data[4:6]))
	if length+8 != int(returned) {
		return "", false, ErrUnavailable
	}
	base, relative := 0, false
	switch tag {
	case windows.IO_REPARSE_TAG_SYMLINK:
		if length < 12 {
			return "", false, ErrUnavailable
		}
		flags := binary.LittleEndian.Uint32(data[16:20])
		if flags > 1 {
			return "", false, ErrUnavailable
		}
		relative, base = flags == 1, 20
	case windows.IO_REPARSE_TAG_MOUNT_POINT:
		if length < 8 {
			return "", false, ErrUnavailable
		}
		base = 16
	default:
		return "", false, ErrUnavailable
	}
	offset := int(binary.LittleEndian.Uint16(data[8:10]))
	count := int(binary.LittleEndian.Uint16(data[10:12]))
	if offset%2 != 0 || count == 0 || count%2 != 0 || base+offset+count > int(returned) {
		return "", false, ErrUnavailable
	}
	encoded := make([]uint16, count/2)
	for index := range encoded {
		encoded[index] = binary.LittleEndian.Uint16(data[base+offset+2*index:])
	}
	// Reject NUL and malformed UTF-16 instead of changing target spelling.
	for index := 0; index < len(encoded); index++ {
		code := encoded[index]
		if code == 0 {
			return "", false, ErrUnavailable
		}
		if code >= 0xd800 && code <= 0xdbff {
			if index+1 == len(encoded) || encoded[index+1] < 0xdc00 || encoded[index+1] > 0xdfff {
				return "", false, ErrUnavailable
			}
			index++
		} else if code >= 0xdc00 && code <= 0xdfff {
			return "", false, ErrUnavailable
		}
	}
	target := string(utf16.Decode(encoded))
	if len(target) > windowsPathLimit {
		return "", false, ErrUnavailable
	}
	return target, relative, nil
}
