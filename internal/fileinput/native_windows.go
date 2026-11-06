//go:build windows

package fileinput

import (
	"errors"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

var reopenFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

type nativeInputPhase uint8

const (
	nativeInputMetadataOpen nativeInputPhase = iota + 1
	nativeInputMetadataState
	nativeInputSameObjectReopen
	nativeInputReaderState
	nativeInputDirectoryName
	nativeInputDirectoryMetadataClose
)

// A phase identifies the failed existing gate, not an individual native call.
// Keep causes available to errors.Is/As without printing native or path details.
type nativeInputFailure struct {
	phase nativeInputPhase
	cause error
}

func (e *nativeInputFailure) Error() string {
	if e == nil {
		return ErrUnavailable.Error()
	}
	switch e.phase {
	case nativeInputMetadataOpen:
		return "selected file input native failure: metadata-open"
	case nativeInputMetadataState:
		return "selected file input native failure: metadata-state"
	case nativeInputSameObjectReopen:
		return "selected file input native failure: sameobject-reopen"
	case nativeInputReaderState:
		return "selected file input native failure: reader-state"
	case nativeInputDirectoryName:
		return "selected file input native failure: directory-name"
	case nativeInputDirectoryMetadataClose:
		return "selected file input native failure: directory-metadata-close"
	default:
		return ErrUnavailable.Error()
	}
}
func (e *nativeInputFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type nativeIDInfo struct {
	Volume uint64
	FileID [16]byte
}

// Validate both the caller spelling and the result of Windows path expansion.
// GetFullPathName (used by filepath.Abs) can turn a DOS reserved name into a
// device namespace, whose complete spelling then becomes filepath.VolumeName.
func validateWindowsNamespace(path string) error {
	if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return ErrUnavailable
	}
	low := strings.ToLower(path)
	for _, prefix := range []string{`\\?\`, `\\.\`, `\??\`, `\device\`, `\global??\`, `\dosdevices\`} {
		if strings.HasPrefix(low, prefix) {
			return ErrUnavailable
		}
	}
	volume := filepath.VolumeName(path)
	if strings.Contains(strings.TrimPrefix(path, volume), ":") {
		return ErrUnavailable
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, volume), `\`) {
		base := strings.ToUpper(strings.SplitN(strings.TrimRight(part, " ."), ".", 2)[0])
		switch base {
		case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
			return ErrUnavailable
		}
		if len(base) > 3 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
			switch base[3:] {
			case "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3":
				return ErrUnavailable
			}
		}
	}
	return nil
}

func absoluteName(path string) (string, error) {
	p := strings.ReplaceAll(path, "/", `\`)
	if e := validateWindowsNamespace(p); e != nil {
		return "", e
	}
	p, e := filepath.Abs(p)
	if e != nil {
		return "", e
	}
	if e = validateWindowsNamespace(p); e != nil {
		return "", e
	}
	if filepath.VolumeName(p) == "" {
		return "", ErrUnavailable
	}
	return p, nil
}
func nativeName(path string) (*uint16, error) {
	p, e := absoluteName(path)
	if e != nil {
		return nil, e
	}
	if len(p) >= 248 {
		if strings.HasPrefix(p, `\\`) {
			p = `\\?\UNC\` + strings.TrimPrefix(p, `\\`)
		} else {
			p = `\\?\` + p
		}
	}
	return windows.UTF16PtrFromString(p)
}
func normalized(e error) error {
	if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_PATH_NOT_FOUND) || errors.Is(e, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(e, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
		return errors.Join(os.ErrNotExist, e)
	}
	return e
}
func stateHandle(h windows.Handle) (fileidentity.State, error) {
	var s fileidentity.State
	k, e := windows.GetFileType(h)
	if e != nil {
		return s, e
	}
	if k != windows.FILE_TYPE_DISK {
		return fileidentity.State{Kind: fileidentity.Other}, nil
	}
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		return s, e
	}
	var id nativeIDInfo
	if e = windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); e != nil {
		return s, e
	}
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	stamp := uint64(info.LastWriteTime.HighDateTime)<<32 | uint64(info.LastWriteTime.LowDateTime)
	if id.FileID == ([16]byte{}) || size > 1<<63-1 || stamp > 1<<63-1 {
		return s, ErrUnavailable
	}
	kind := fileidentity.Regular
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		kind = fileidentity.Reparse
	} else if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		kind = fileidentity.Directory
	} else if info.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 {
		kind = fileidentity.Other
	}
	return fileidentity.State{ID: fileidentity.ID{Volume: id.Volume, FileID: id.FileID}, Kind: kind, Size: int64(size), Modified: time.Unix(int64(stamp/10000000)-11644473600, int64(stamp%10000000)*100).UTC()}, nil
}
func stateFromFile(f *os.File) (s fileidentity.State, e error) {
	if f == nil {
		return s, ErrUnavailable
	}
	c, e := f.SyscallConn()
	if e != nil {
		return s, e
	}
	var q error
	e = c.Control(func(raw uintptr) { s, q = stateHandle(windows.Handle(raw)) })
	return s, errors.Join(e, q)
}
func metadata(path string, follow bool) (*os.File, error) {
	name, e := nativeName(path)
	if e != nil {
		return nil, e
	}
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_NO_RECALL)
	if !follow {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, e := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if e != nil {
		return nil, normalized(e)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		return nil, errors.Join(ErrUnavailable, windows.CloseHandle(h))
	}
	return f, nil
}
func stateFromPath(path string, follow bool) (s fileidentity.State, e error) {
	f, e := metadata(path, follow)
	if e != nil {
		return s, e
	}
	s, q := stateFromFile(f)
	return s, errors.Join(q, f.Close())
}
func reopen(meta *os.File, path string, share uint32) (*os.File, error) {
	c, e := meta.SyscallConn()
	if e != nil {
		return nil, e
	}
	var h windows.Handle
	var q error
	e = c.Control(func(raw uintptr) {
		// Keep data/directory reopen flags minimal. Recall or caching may occur;
		// metadata handles separately retain their no-recall request.
		value, _, cause := reopenFile.Call(raw, uintptr(windows.GENERIC_READ), uintptr(share), uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT))
		h = windows.Handle(value)
		if h == windows.InvalidHandle || h == 0 {
			if cause == syscall.Errno(0) {
				cause = ErrUnavailable
			}
			q = cause
		}
	})
	if e != nil || q != nil {
		if h != 0 && h != windows.InvalidHandle {
			return nil, errors.Join(e, q, windows.CloseHandle(h))
		}
		return nil, errors.Join(e, q)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		return nil, errors.Join(ErrUnavailable, windows.CloseHandle(h))
	}
	return f, nil
}
func openKind(path string, kind fileidentity.Kind, share uint32) (reader, meta *os.File, err error) {
	meta, err = metadata(path, false)
	if err != nil {
		return nil, nil, &nativeInputFailure{phase: nativeInputMetadataOpen, cause: err}
	}
	good := false
	var failurePhase nativeInputPhase
	defer func() {
		if !good {
			if reader != nil {
				err = errors.Join(err, reader.Close())
				reader = nil
			}
			err = errors.Join(err, meta.Close())
			meta = nil
			// Wrap last so cleanup cofailures remain causes rather than printed data.
			err = &nativeInputFailure{phase: failurePhase, cause: err}
		}
	}()
	before, e := stateFromFile(meta)
	if e != nil || before.Kind != kind {
		failurePhase = nativeInputMetadataState
		return nil, meta, errors.Join(ErrUnavailable, e)
	}
	reader, err = reopen(meta, path, share)
	if err != nil {
		failurePhase = nativeInputSameObjectReopen
		return nil, meta, err
	}
	after, e := stateFromFile(reader)
	if e != nil || after.Kind != kind || before.ID != after.ID || before.Size != after.Size || !before.Modified.Equal(after.Modified) {
		failurePhase = nativeInputReaderState
		return reader, meta, errors.Join(ErrUnavailable, e)
	}
	good = true
	return reader, meta, nil
}
func openInput(path string) (input, error) {
	reader, meta, e := openKind(path, fileidentity.Regular, windows.FILE_SHARE_READ)
	if e != nil {
		return nil, e
	}
	return &fileOwner{File: reader, metadata: meta}, nil
}
func openDirectory(path string) (*os.File, error) {
	name, e := absoluteName(path)
	if e != nil {
		return nil, &nativeInputFailure{phase: nativeInputDirectoryName, cause: e}
	}
	reader, meta, e := openKind(name, fileidentity.Directory, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if e != nil {
		return nil, e
	}
	if e = meta.Close(); e != nil {
		return nil, &nativeInputFailure{phase: nativeInputDirectoryMetadataClose, cause: errors.Join(e, reader.Close())}
	}
	return reader, nil
}
func stateAt(parent *os.File, name string, follow bool) (s fileidentity.State, e error) {
	if strings.ContainsAny(name, `\/:`) {
		return s, ErrUnavailable
	}
	child, e := windows.NewNTUnicodeString(name)
	if e != nil {
		return s, e
	}
	c, e := parent.SyscallConn()
	if e != nil {
		return s, e
	}
	var q error
	e = c.Control(func(raw uintptr) {
		oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(raw), ObjectName: child, Attributes: windows.OBJ_CASE_INSENSITIVE}
		var iosb windows.IO_STATUS_BLOCK
		var h windows.Handle
		options := uint32(windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
		if !follow {
			options |= windows.FILE_OPEN_REPARSE_POINT
		}
		options |= 0x00400000 // FILE_OPEN_NO_RECALL (NT option).
		q = windows.NtCreateFile(&h, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, &oa, &iosb, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, options, 0, 0)
		if q != nil {
			q = normalized(q)
			return
		}
		s, q = stateHandle(h)
		q = errors.Join(q, windows.CloseHandle(h))
	})
	return s, errors.Join(e, q)
}
