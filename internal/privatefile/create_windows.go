//go:build windows

package privatefile

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errHistoryExportPrivate = errors.New("private workflow history export file is unavailable")

func historyExportProcessContext() error {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err == nil {
		return errors.Join(errHistoryExportPrivate, token.Close())
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return errors.Join(errHistoryExportPrivate, err)
	}
	return nil
}

// Caller pins its OS thread. No token, privilege, account or profile changes.
func historyExportProcessSID() (sid string, failure error) {
	if err := historyExportProcessContext(); err != nil {
		return "", err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "", errors.Join(errHistoryExportPrivate, err)
	}
	defer func() {
		if err := token.Close(); err != nil {
			sid = ""
			failure = errors.Join(errHistoryExportPrivate, failure, err)
		}
	}()
	var kind, size uint32
	if windows.GetTokenInformation(token, windows.TokenType, (*byte)(unsafe.Pointer(&kind)), uint32(unsafe.Sizeof(kind)), &size) != nil || size != uint32(unsafe.Sizeof(kind)) || kind != windows.TokenPrimary {
		return "", errHistoryExportPrivate
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", errors.Join(errHistoryExportPrivate, err)
	}
	sid = user.User.Sid.String()
	runtime.KeepAlive(user)
	if sid == "" || strings.HasPrefix(sid, "S-1-3-") {
		return "", errHistoryExportPrivate
	}
	if err := historyExportProcessContext(); err != nil {
		return "", err
	}
	return sid, nil
}

// Validate the self-relative native allocation before deriving an ACE/SID
// pointer. The only permitted entries are explicit full-control user+SYSTEM.
func checkHistoryExportDescriptor(sd *windows.SECURITY_DESCRIPTOR, owner string) error {
	if sd == nil || !sd.IsValid() {
		return errHistoryExportPrivate
	}
	defer runtime.KeepAlive(sd)
	control, revision, err := sd.Control()
	if err != nil || revision != 1 || control&(windows.SE_SELF_RELATIVE|windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED) != windows.SE_SELF_RELATIVE|windows.SE_DACL_PRESENT|windows.SE_DACL_PROTECTED {
		return errHistoryExportPrivate
	}
	length := sd.Length()
	if length < 20 || length > 65536 {
		return errHistoryExportPrivate
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(length))
	if data[0] != 1 || data[1] != 0 {
		return errHistoryExportPrivate
	}
	ownerOffset := int(binary.LittleEndian.Uint32(data[4:8]))
	aclOffset := int(binary.LittleEndian.Uint32(data[16:20]))
	sidText := func(bytes []byte) (string, int, bool) {
		if len(bytes) < 8 || bytes[0] != 1 || bytes[1] > 15 {
			return "", 0, false
		}
		size := 8 + 4*int(bytes[1])
		if size > len(bytes) {
			return "", 0, false
		}
		sid := (*windows.SID)(unsafe.Pointer(&bytes[0]))
		if !sid.IsValid() {
			return "", 0, false
		}
		text := sid.String()
		return text, size, text != ""
	}
	if ownerOffset < 20 || ownerOffset&3 != 0 || ownerOffset >= len(data) || aclOffset < 20 || aclOffset&3 != 0 || aclOffset > len(data)-8 {
		return errHistoryExportPrivate
	}
	actualOwner, ownerSize, ok := sidText(data[ownerOffset:])
	if !ok || actualOwner != owner {
		return errHistoryExportPrivate
	}
	acl := data[aclOffset:]
	aclSize := int(binary.LittleEndian.Uint16(acl[2:4]))
	if acl[0] != 2 && acl[0] != 4 || acl[1] != 0 || binary.LittleEndian.Uint16(acl[6:8]) != 0 || aclSize < 8 || aclSize&3 != 0 || aclSize > len(acl) || binary.LittleEndian.Uint16(acl[4:6]) != 2 {
		return errHistoryExportPrivate
	}
	if ownerOffset < aclOffset+aclSize && aclOffset < ownerOffset+ownerSize {
		return errHistoryExportPrivate
	}
	acl = acl[:aclSize]
	cursor := 8
	seenOwner, seenSystem := false, false
	for index := 0; index < 2; index++ {
		if cursor > len(acl)-8 {
			return errHistoryExportPrivate
		}
		ace := acl[cursor:]
		size := int(binary.LittleEndian.Uint16(ace[2:4]))
		if size < 16 || size&3 != 0 || size > len(ace) || ace[0] != windows.ACCESS_ALLOWED_ACE_TYPE || ace[1] != 0 || binary.LittleEndian.Uint32(ace[4:8]) != 0x001f01ff {
			return errHistoryExportPrivate
		}
		principal, sidSize, ok := sidText(ace[8:size])
		if !ok || sidSize != size-8 || principal != owner && principal != "S-1-5-18" {
			return errHistoryExportPrivate
		}
		if principal == owner {
			seenOwner = true
		}
		if principal == "S-1-5-18" {
			seenSystem = true
		}
		cursor += size
	}
	if cursor != len(acl) || !seenOwner || !seenSystem {
		return errHistoryExportPrivate
	}
	return nil
}

func Create(path string) (file *os.File, failure error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !utf8.ValidString(path) {
		return nil, errHistoryExportPrivate
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errHistoryExportPrivate
	}
	volume := filepath.VolumeName(absolute)
	if !filepath.IsLocal(filepath.Base(absolute)) || strings.Contains(strings.TrimPrefix(absolute, volume), ":") || strings.HasPrefix(absolute, `\\.\`) {
		return nil, errHistoryExportPrivate
	}
	owner, err := historyExportProcessSID()
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)")
	if err != nil || checkHistoryExportDescriptor(descriptor, owner) != nil {
		return nil, errors.Join(errHistoryExportPrivate, err)
	}
	name, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return nil, errHistoryExportPrivate
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, 0, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	owned := true
	defer func() {
		if owned {
			if err := windows.CloseHandle(handle); err != nil {
				file = nil
				failure = errors.Join(errHistoryExportPrivate, failure, err)
			}
		}
	}()
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		return nil, errors.Join(errHistoryExportPrivate, err)
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow != 0 {
		return nil, errHistoryExportPrivate
	}
	observed, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || checkHistoryExportDescriptor(observed, owner) != nil {
		return nil, errors.Join(errHistoryExportPrivate, err)
	}
	after, err := historyExportProcessSID()
	if err != nil || after != owner {
		return nil, errors.Join(errHistoryExportPrivate, err)
	}
	file = os.NewFile(uintptr(handle), path)
	if file == nil {
		return nil, errHistoryExportPrivate
	}
	owned = false
	return file, nil
}
