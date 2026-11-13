//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/nativepath"
	"github.com/Yunushan/accessweaver/internal/uiaccess"
	"github.com/Yunushan/accessweaver/internal/wintrust"
	"golang.org/x/sys/windows"
)

// Alternate-account operations exist only in this exact-opt-in source fixture.
// No installed product, policy, privilege or logon right is changed.
const ordinaryWorkerArgument = "--accessweaver-ordinary-native-worker-v1"
const ordinaryProfileKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
const ordinaryAdministrator = "S-1-5-32-544"
const ordinaryAncestorMutation uint32 = 0x500d0152
const ordinaryPipeAccess uint32 = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE

var ordinaryUser32 = windows.NewLazySystemDLL("user32.dll")
var ordinaryUserenv = windows.NewLazySystemDLL("userenv.dll")
var ordinaryAdvapi = windows.NewLazySystemDLL("advapi32.dll")
var ordinaryNet = windows.NewLazySystemDLL("netapi32.dll")
var ordinaryKernel = windows.NewLazySystemDLL("kernel32.dll")
var ordinaryNT = windows.NewLazySystemDLL("ntdll.dll")
var ordinaryMagic = [8]byte{'A', 'W', 'O', 'r', 'd', '0', '1', '!'}
var errOrdinary = errors.New("ordinary Windows fixture operation failed")

type ordinaryUser1 struct {
	name, password         *uint16
	passwordAge, privilege uint32
	home, comment          *uint16
	flags                  uint32
	script                 *uint16
}
type ordinaryUser23 struct {
	name, fullName, comment *uint16
	flags                   uint32
	sid                     *windows.SID
}
type ordinaryCase struct {
	ID       string `json:"id"`
	Executed bool   `json:"executed"`
	Passed   bool   `json:"passed"`
}
type ordinaryObject struct {
	path, owner string
	id          fileidentity.ID
}
type ordinaryAccounting struct {
	User, Kernel, PeriodUser, PeriodKernel int64
	Faults, Total, Active, Terminated      uint32
}
type ordinaryPending struct {
	pin     runtime.Pinner
	overlap windows.Overlapped
	buffer  []byte
	event   windows.Handle
}

// Unconfirmed cancellation must retain kernel-referenced Go memory and events.
// It fails cleanup; it is never disguised as a successful bounded operation.
var ordinaryUnfinishedIO []*ordinaryPending
var ordinaryCloseFailure bool

// The worker may publish only these fixed labels for a failed desktop assertion.
type windowsDesktopStage byte

const (
	windowsDesktopNoFailure windowsDesktopStage = iota
	windowsDesktopStream
	windowsDesktopStartup
	windowsDesktopLaunchPath
	windowsDesktopLaunchFileACL
	windowsDesktopLaunchDirectoryACL
	windowsDesktopLaunchContents
	windowsDesktopHTTPAdmission
	windowsDesktopHTTPMutation
	windowsDesktopHTTPDenials
	windowsDesktopShutdown
	windowsDesktopCleanup
	windowsDesktopJournal
	windowsDesktopExport
	windowsDesktopReopen
)

var windowsDesktopStageNames = [...]string{
	windowsDesktopNoFailure:          "none",
	windowsDesktopStream:             "stream",
	windowsDesktopStartup:            "startup",
	windowsDesktopLaunchPath:         "launch-path",
	windowsDesktopLaunchFileACL:      "launch-file-acl",
	windowsDesktopLaunchDirectoryACL: "launch-directory-acl",
	windowsDesktopLaunchContents:     "launch-contents",
	windowsDesktopHTTPAdmission:      "http-admission",
	windowsDesktopHTTPMutation:       "http-mutation",
	windowsDesktopHTTPDenials:        "http-denials",
	windowsDesktopShutdown:           "shutdown",
	windowsDesktopCleanup:            "cleanup",
	windowsDesktopJournal:            "journal",
	windowsDesktopExport:             "export",
	windowsDesktopReopen:             "reopen",
}

const ordinaryReplySize = 56

type ordinaryFixture struct {
	desktopFailure                                                       windowsDesktopStage
	commands, policyInstalled, policyRemoved, privateChildRemoved        bool
	childSlot                                                            string
	cleanupPolicy                                                        func() error
	cases                                                                []ordinaryCase
	objects                                                              []ordinaryObject
	account                                                              []uint16
	sid, setupSID, root, image, profile, profilesRoot                    string
	profileObject                                                        ordinaryObject
	profileParents                                                       []ordinaryObject
	profileBaseline                                                      map[string]fileidentity.ID
	profileBaselineRoot                                                  ordinaryObject
	password                                                             []uint16
	imageHash                                                            [32]byte
	process, thread, job, pipe, station, desktop                         windows.Handle
	pid                                                                  uint32
	accountCreated, accountRemoved, profileAbsentBefore, profileCaptured bool
	stagingCreated                                                       bool
	profileRemoved, stagingRemoved, processesEmpty, processExited        bool
	guiClosed, handlesClosed, cleanupOK, usersAdded, jobAssigned         bool
}

var ordinaryCaseNames = []string{
	"host-context", "fresh-normal-account", "protected-source-staging",
	"private-windowstation-desktop", "suspended-primary-token", "bound-loaded-profile",
	"held-job-before-resume", "pid-bound-pipe", "worker-primary-token",
	"worker-loaded-profile-hkcu", "worker-native-image",
	"worker-isolated-console-interrupt", "worker-public-recording-support-contract",
	"worker-exit", "exact-owned-cleanup",
}

func (f *ordinaryFixture) check(id string, body func() error) error {
	for i := range f.cases {
		if f.cases[i].ID == id {
			f.cases[i].Executed = true
			err := body()
			f.cases[i].Passed = err == nil
			return err
		}
	}
	return errOrdinary
}
func ordinaryClose(handle *windows.Handle) bool {
	if *handle == 0 || *handle == windows.InvalidHandle {
		return true
	}
	err := windows.CloseHandle(*handle)
	if err != nil {
		ordinaryCloseFailure = true
	}
	*handle = 0
	return err == nil
}
func ordinaryNoImpersonation() bool {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err == nil {
		if token.Close() != nil {
			ordinaryCloseFailure = true
		}
		return false
	}
	return errors.Is(err, windows.ERROR_NO_TOKEN)
}
func ordinaryToken(token windows.Token, expected string, administrator bool) bool {
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() || user.User.Sid.String() != expected {
		return false
	}
	var elevation, kind, count uint32
	if windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), 4, &count) != nil || count != 4 || elevation > 1 || (elevation == 1) != administrator {
		return false
	}
	if windows.GetTokenInformation(token, windows.TokenType, (*byte)(unsafe.Pointer(&kind)), 4, &count) != nil || count != 4 || kind != windows.TokenPrimary {
		return false
	}
	restricted, err := token.IsRestricted()
	if err != nil || restricted {
		return false
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	var users, admins bool
	for _, group := range groups.AllGroups() {
		if group.Sid == nil || !group.Sid.IsValid() {
			return false
		}
		value := group.Sid.String()
		if value == ordinaryAdministrator {
			admins = true
		}
		if value == "S-1-5-32-545" && group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			users = true
		}
	}
	runtime.KeepAlive(groups)
	return admins == administrator && (administrator || users)
}
func ordinaryNative() bool {
	machine := map[string]uint16{"amd64": 0x8664, "arm64": 0xaa64}[runtime.GOARCH]
	var process, native uint16
	return machine != 0 && windows.IsWow64Process2(windows.CurrentProcess(), &process, &native) == nil && process == 0 && native == machine
}
func ordinaryAccountSID(name []uint16) (string, error) {
	if len(name) < 2 {
		return "", errOrdinary
	}
	var buffer *byte
	err := windows.NetUserGetInfo(nil, &name[0], 23, &buffer)
	if err != nil || buffer == nil {
		if buffer != nil {
			_ = windows.NetApiBufferFree(buffer)
		}
		return "", errOrdinary
	}
	info := (*ordinaryUser23)(unsafe.Pointer(buffer))
	value := ""
	if info.sid != nil && info.sid.IsValid() {
		value = info.sid.String()
	}
	if windows.NetApiBufferFree(buffer) != nil || value == "" {
		return "", errOrdinary
	}
	return value, nil
}
func ordinaryRegistryAbsent(root windows.Handle, path string) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var key windows.Handle
	err = windows.RegOpenKeyEx(root, name, 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &key)
	if err == nil {
		if windows.RegCloseKey(key) != nil {
			ordinaryCloseFailure = true
		}
		return false
	}
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}
func ordinaryRegistryString(root windows.Handle, path, value string, protected bool) (result string, failure error) {
	name, _ := windows.UTF16PtrFromString(path)
	var key windows.Handle
	if windows.RegOpenKeyEx(root, name, 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &key) != nil {
		return "", errOrdinary
	}
	defer func() {
		if windows.RegCloseKey(key) != nil {
			ordinaryCloseFailure = true
			result, failure = "", errOrdinary
		}
	}()
	if protected && wintrust.CheckHandle(syscall.Handle(key), 4, wintrust.RegistryMutationRights) != nil {
		return "", errOrdinary
	}
	valueName, _ := windows.UTF16PtrFromString(value)
	var kind, size uint32
	if windows.RegQueryValueEx(key, valueName, nil, &kind, nil, &size) != nil || size < 2 || size > 65536 || size%2 != 0 || (kind != windows.REG_SZ && kind != windows.REG_EXPAND_SZ) {
		return "", errOrdinary
	}
	buffer := make([]uint16, size/2)
	if windows.RegQueryValueEx(key, valueName, nil, &kind, (*byte)(unsafe.Pointer(&buffer[0])), &size) != nil || size < 2 || size > uint32(len(buffer)*2) || size%2 != 0 || (kind != windows.REG_SZ && kind != windows.REG_EXPAND_SZ) {
		return "", errOrdinary
	}
	buffer = buffer[:size/2]
	if buffer[len(buffer)-1] != 0 {
		return "", errOrdinary
	}
	for _, ch := range buffer[:len(buffer)-1] {
		if ch == 0 {
			return "", errOrdinary
		}
	}
	result = windows.UTF16ToString(buffer)
	if kind == windows.REG_EXPAND_SZ {
		system, err := nativepath.SystemDirectory()
		if err != nil {
			return "", errOrdinary
		}
		variables := map[string]string{"%SYSTEMDRIVE%": filepath.VolumeName(system), "%SYSTEMROOT%": filepath.Dir(system), "%WINDIR%": filepath.Dir(system)}
		for {
			start := strings.IndexByte(result, '%')
			if start < 0 {
				break
			}
			end := strings.IndexByte(result[start+1:], '%')
			if end < 0 {
				return "", errOrdinary
			}
			end += start + 2
			replacement, ok := variables[strings.ToUpper(result[start:end])]
			if !ok {
				return "", errOrdinary
			}
			result = result[:start] + replacement + result[end:]
		}
	}
	if !filepath.IsAbs(result) || filepath.Clean(result) != result || len(filepath.VolumeName(result)) != 2 || strings.Contains(result[2:], ":") {
		return "", errOrdinary
	}
	return result, nil
}
func ordinaryOpen(path string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, errOrdinary
	}
	h, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, errOrdinary
	}
	return h, nil
}
func ordinaryState(path string, handle windows.Handle) (ordinaryObject, error) {
	var filesystem [16]uint16
	var volumeFlags uint32
	kind, kindErr := windows.GetFileType(handle)
	if kindErr != nil || kind != windows.FILE_TYPE_DISK || windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &volumeFlags, &filesystem[0], uint32(len(filesystem))) != nil || windows.UTF16ToString(filesystem[:]) != "NTFS" || volumeFlags&windows.FILE_PERSISTENT_ACLS == 0 {
		return ordinaryObject{}, errOrdinary
	}
	var info struct {
		Volume uint64
		ID     [16]byte
	}
	var attributes windows.ByHandleFileInformation
	if windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))) != nil || info.ID == ([16]byte{}) || windows.GetFileInformationByHandle(handle, &attributes) != nil || attributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ordinaryObject{}, errOrdinary
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !sd.IsValid() {
		return ordinaryObject{}, errOrdinary
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return ordinaryObject{}, errOrdinary
	}
	result := ordinaryObject{path: path, owner: owner.String(), id: fileidentity.ID{Volume: info.Volume, FileID: info.ID}}
	runtime.KeepAlive(sd)
	return result, nil
}
func ordinarySameObject(object ordinaryObject, access uint32) (windows.Handle, error) {
	h, err := ordinaryOpen(object.path, access|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		return 0, errOrdinary
	}
	state, err := ordinaryState(object.path, h)
	if err != nil || state.id != object.id || state.owner != object.owner {
		if windows.CloseHandle(h) != nil {
			ordinaryCloseFailure = true
		}
		return 0, errOrdinary
	}
	return h, nil
}
func ordinaryTrustedDirectory(path, child string) (object ordinaryObject, failure error) {
	h, err := ordinaryOpen(path, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		return ordinaryObject{}, errOrdinary
	}
	defer func() {
		if windows.CloseHandle(h) != nil {
			ordinaryCloseFailure = true
			object, failure = ordinaryObject{}, errOrdinary
		}
	}()
	state, err := ordinaryState(path, h)
	if err != nil {
		return ordinaryObject{}, errOrdinary
	}
	var attributes windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &attributes) != nil || attributes.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ordinaryObject{}, errOrdinary
	}
	if child == "" {
		if wintrust.CheckHandle(syscall.Handle(h), 1, ordinaryAncestorMutation) != nil {
			return ordinaryObject{}, errOrdinary
		}
	} else {
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || !ordinaryDescriptor(sd, child, false) {
			return ordinaryObject{}, errOrdinary
		}
	}
	return state, nil
}

// GetAce bounds ACEs in OS-returned, IsValid security descriptors.
func ordinaryDescriptor(sd *windows.SECURITY_DESCRIPTOR, child string, exclusive bool) bool {
	if sd == nil || !sd.IsValid() {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() || (!wintrust.TrustedSID(owner.String()) && owner.String() != child) {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || (exclusive && control&windows.SE_DACL_PROTECTED == 0) {
		return false
	}
	header := (*struct {
		Revision, Reserved     byte
		Size, Count, Reserved2 uint16
	})(unsafe.Pointer(acl))
	if header.Size < 8 || header.Count > 512 {
		return false
	}
	for index := uint16(0); index < header.Count; index++ {
		var raw unsafe.Pointer
		ok, _, _ := ordinaryAdvapi.NewProc("GetAce").Call(uintptr(unsafe.Pointer(acl)), uintptr(index), uintptr(unsafe.Pointer(&raw)))
		if ok == 0 || raw == nil {
			return false
		}
		ace := (*windows.ACCESS_ALLOWED_ACE)(raw)
		if ace.Header.AceSize < 16 || (ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE) {
			return false
		}
		principal := (*windows.SID)(unsafe.Add(raw, 8))
		if !principal.IsValid() || uint32(ace.Header.AceSize) < 8+uint32(principal.Len()) {
			return false
		}
		value := principal.String()
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE && !exclusive {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		if value == "S-1-3-4" {
			value = owner.String()
		}
		if exclusive {
			if !wintrust.TrustedSID(value) && value != child {
				return false
			}
		} else if uint32(ace.Mask)&ordinaryAncestorMutation != 0 && !wintrust.TrustedSID(value) && value != child {
			return false
		}
	}
	runtime.KeepAlive(sd)
	return true
}
func ordinaryImageHash(path string) ([32]byte, error) {
	var result [32]byte
	file, err := os.Open(path)
	if err != nil {
		return result, errOrdinary
	}
	digest := sha256.New()
	n, readErr := io.Copy(digest, io.LimitReader(file, (128<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || n < 1 || n > 128<<20 {
		return result, errOrdinary
	}
	copy(result[:], digest.Sum(nil))
	return result, nil
}
func ordinaryDigits(value string) bool {
	return len(value) > 0 && len(value) <= 24 && strings.Trim(value, "0123456789") == ""
}
func (f *ordinaryFixture) record(path string) error {
	handle, err := ordinaryOpen(path, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		f.cleanupOK = false
		return errOrdinary
	}
	state, stateErr := ordinaryState(path, handle)
	closeErr := windows.CloseHandle(handle)
	if stateErr != nil || closeErr != nil || state.owner != ordinaryAdministrator {
		f.cleanupOK = false
		return errOrdinary
	}
	f.objects = append(f.objects, state)
	return nil
}

// prepare records ownership at each exclusive creation, including partial setup.
func (f *ordinaryFixture) prepare() error {
	if err := f.check("host-context", func() error {
		if os.Getenv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_ORDINARY_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || !ordinaryNative() || os.Getenv("ACCESSWEAVER_EXPECT_GOOS") != "windows" || os.Getenv("ACCESSWEAVER_EXPECT_GOARCH") != runtime.GOARCH || os.Getenv("RUNNER_ARCH") != map[string]string{"amd64": "X64", "arm64": "ARM64"}[runtime.GOARCH] || runtime.Version() != "go"+os.Getenv("GO_VERSION") || os.Getenv("GOTOOLCHAIN") != "local" {
			return errOrdinary
		}
		commit := os.Getenv("GITHUB_SHA")
		decoded, err := hex.DecodeString(commit)
		if err != nil || (len(decoded) != 20 && len(decoded) != 32) || strings.ToLower(commit) != commit || !ordinaryDigits(os.Getenv("GITHUB_RUN_ID")) || !ordinaryDigits(os.Getenv("GITHUB_RUN_ATTEMPT")) {
			return errOrdinary
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if !ordinaryNoImpersonation() {
			return errOrdinary
		}
		var token windows.Token
		if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
			return errOrdinary
		}
		user, err := token.GetTokenUser()
		if err != nil || user == nil || user.User.Sid == nil {
			if token.Close() != nil {
				ordinaryCloseFailure = true
			}
			return errOrdinary
		}
		f.setupSID = user.User.Sid.String()
		valid := f.setupSID != "S-1-5-18" && ordinaryToken(token, f.setupSID, true)
		closed := token.Close()
		if !valid || closed != nil {
			return errOrdinary
		}
		return nil
	}); err != nil {
		return err
	}
	if err := f.check("fresh-normal-account", func() error {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return errOrdinary
		}
		defer clear(random[:])
		f.account, _ = windows.UTF16FromString("awo" + hex.EncodeToString(random[:8]))
		f.password = make([]uint16, 69)
		copy(f.password, []uint16{'A', 'a', '1', '!'})
		const digits = "0123456789abcdef"
		for i, b := range random {
			f.password[4+2*i] = uint16(digits[b>>4])
			f.password[5+2*i] = uint16(digits[b&15])
		}
		info := ordinaryUser1{name: &f.account[0], password: &f.password[0], privilege: 1, flags: 0x0201}
		var parameter uint32
		status, _, _ := ordinaryNet.NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
		runtime.KeepAlive(f.password)
		if status != 0 {
			return errOrdinary
		}
		f.accountCreated = true
		var err error
		f.sid, err = ordinaryAccountSID(f.account)
		if err != nil || f.sid == f.setupSID {
			return errOrdinary
		}
		users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
		if err != nil {
			return errOrdinary
		}
		alias, _, _, err := users.LookupAccount("")
		if err != nil || alias == "" {
			return errOrdinary
		}
		aliasName, _ := windows.UTF16PtrFromString(alias)
		sid, err := windows.StringToSid(f.sid)
		if err != nil {
			return errOrdinary
		}
		entry := struct{ SID *windows.SID }{sid}
		status, _, _ = ordinaryNet.NewProc("NetLocalGroupAddMembers").Call(0, uintptr(unsafe.Pointer(aliasName)), 0, uintptr(unsafe.Pointer(&entry)), 1)
		runtime.KeepAlive(sid)
		if status != 0 && status != 1378 {
			return errOrdinary
		} // ERROR_MEMBER_IN_ALIAS
		f.usersAdded = status == 0
		f.profileAbsentBefore = ordinaryRegistryAbsent(windows.HKEY_LOCAL_MACHINE, ordinaryProfileKey+"\\"+f.sid) && ordinaryRegistryAbsent(windows.HKEY_USERS, f.sid) && ordinaryRegistryAbsent(windows.HKEY_USERS, f.sid+"_Classes")
		if !f.profileAbsentBefore {
			return errOrdinary
		}
		return f.snapshotProfiles()
	}); err != nil {
		return err
	}
	return f.check("protected-source-staging", func() error {
		programs, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
		if err != nil {
			return errOrdinary
		}
		for current := programs; ; current = filepath.Dir(current) {
			if _, err := ordinaryTrustedDirectory(current, ""); err != nil {
				return errOrdinary
			}
			if filepath.Dir(current) == current {
				break
			}
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return errOrdinary
		}
		f.root = filepath.Join(programs, "AccessWeaverOrdinaryTest-"+hex.EncodeToString(random[:]))
		sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FRFX;;;" + f.sid + ")")
		if err != nil {
			return errOrdinary
		}
		sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		name, _ := windows.UTF16PtrFromString(f.root)
		if windows.CreateDirectory(name, &sa) != nil {
			return errOrdinary
		}
		f.stagingCreated = true
		if err := f.record(f.root); err != nil {
			return err
		}
		f.image = filepath.Join(f.root, "source.test.exe")
		source, err := os.Executable()
		if err != nil {
			return errOrdinary
		}
		f.imageHash, err = ordinaryImageHash(source)
		if err != nil {
			return err
		}
		input, err := os.Open(source)
		if err != nil {
			return errOrdinary
		}
		destination, _ := windows.UTF16PtrFromString(f.image)
		handle, err := windows.CreateFile(destination, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0)
		runtime.KeepAlive(sd)
		if err != nil {
			_ = input.Close()
			return errOrdinary
		}
		file := os.NewFile(uintptr(handle), f.image)
		recordErr := f.record(f.image)
		n, copyErr := io.Copy(file, io.LimitReader(input, (128<<20)+1))
		flushErr := windows.FlushFileBuffers(handle)
		inputErr, outputErr := input.Close(), file.Close()
		if recordErr != nil || copyErr != nil || flushErr != nil || inputErr != nil || outputErr != nil || n < 1 || n > 128<<20 {
			return errOrdinary
		}
		staged, err := ordinaryImageHash(f.image)
		if err != nil || staged != f.imageHash {
			return errOrdinary
		}
		return nil
	})
}

func ordinaryUserObjectName(handle windows.Handle) (string, error) {
	var buffer [256]uint16
	var size uint32
	ok, _, _ := ordinaryUser32.NewProc("GetUserObjectInformationW").Call(uintptr(handle), 2, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)*2), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size < 2 || size > uint32(len(buffer)*2) {
		return "", errOrdinary
	}
	return windows.UTF16ToString(buffer[:size/2]), nil
}
func (f *ordinaryFixture) privateDesktop() (name string, failure error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !ordinaryNoImpersonation() {
		return "", errOrdinary
	}
	originalStation, _, _ := ordinaryUser32.NewProc("GetProcessWindowStation").Call()
	originalDesktop, _, _ := ordinaryUser32.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
	if originalStation == 0 || originalDesktop == 0 {
		return "", errOrdinary
	}
	// The process switch is confined to this dedicated non-parallel test process.
	// Restore the process station first; desktop restoration is needed only if
	// CreateDesktop actually changed the creating thread's association.
	defer func() {
		ok, _, _ := ordinaryUser32.NewProc("SetProcessWindowStation").Call(originalStation)
		if ok == 0 {
			failure = errOrdinary
			f.cleanupOK = false
			return
		}
		current, _, _ := ordinaryUser32.NewProc("GetThreadDesktop").Call(uintptr(windows.GetCurrentThreadId()))
		if current != originalDesktop {
			ok, _, _ = ordinaryUser32.NewProc("SetThreadDesktop").Call(originalDesktop)
			if ok == 0 {
				failure = errOrdinary
				f.cleanupOK = false
			}
		}
	}()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", errOrdinary
	}
	stationName := "AccessWeaverOrdinary-" + hex.EncodeToString(random[:])
	stationUTF, _ := windows.UTF16PtrFromString(stationName)
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;" + f.sid + ")")
	if err != nil {
		return "", errOrdinary
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	station, _, _ := ordinaryUser32.NewProc("CreateWindowStationW").Call(uintptr(unsafe.Pointer(stationUTF)), 1, uintptr(windows.GENERIC_ALL), uintptr(unsafe.Pointer(&sa))) // CWF_CREATE_ONLY
	if station == 0 {
		return "", errOrdinary
	}
	f.station = windows.Handle(station)
	actual, err := ordinaryUserObjectName(f.station)
	if err != nil || actual != stationName {
		return "", errOrdinary
	}
	ok, _, _ := ordinaryUser32.NewProc("SetProcessWindowStation").Call(station)
	if ok == 0 {
		return "", errOrdinary
	}
	desktopName, _ := windows.UTF16PtrFromString("ordinary")
	desktop, _, _ := ordinaryUser32.NewProc("CreateDesktopW").Call(uintptr(unsafe.Pointer(desktopName)), 0, 0, 0, uintptr(windows.GENERIC_ALL), uintptr(unsafe.Pointer(&sa)))
	runtime.KeepAlive(sd)
	if desktop == 0 {
		return "", errOrdinary
	}
	f.desktop = windows.Handle(desktop)
	for _, handle := range []windows.Handle{f.station, f.desktop} {
		observed, err := windows.GetSecurityInfo(handle, windows.SE_WINDOW_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || !ordinaryDescriptor(observed, f.sid, true) {
			return "", errOrdinary
		}
	}
	return stationName + "\\ordinary", nil
}

// A fresh SID alone does not rule out orphaned filesystem profile directories.
// Capture only bounded immediate names/IDs, never another profile's contents.
func (f *ordinaryFixture) snapshotProfiles() error {
	root, err := ordinaryRegistryString(windows.HKEY_LOCAL_MACHINE, ordinaryProfileKey, "ProfilesDirectory", true)
	if err != nil {
		return errOrdinary
	}
	bound, err := ordinaryTrustedDirectory(root, "")
	if err != nil {
		return errOrdinary
	}
	for current := filepath.Dir(root); ; current = filepath.Dir(current) {
		if _, err := ordinaryTrustedDirectory(current, ""); err != nil {
			return errOrdinary
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	directory, err := os.Open(root)
	if err != nil {
		return errOrdinary
	}
	entries, readErr := directory.ReadDir(513)
	closeErr := directory.Close()
	if closeErr != nil || (readErr != nil && !errors.Is(readErr, io.EOF)) || len(entries) > 512 {
		return errOrdinary
	}
	baseline := make(map[string]fileidentity.ID, len(entries))
	total := 0
	for _, entry := range entries {
		total += len(entry.Name())
		if total > 65536 {
			return errOrdinary
		}
		state, err := fileidentity.FromPath(filepath.Join(root, entry.Name()), false)
		if err != nil || state.ID == (fileidentity.ID{}) {
			return errOrdinary
		}
		baseline[strings.ToLower(entry.Name())] = state.ID
	}
	after, err := ordinaryTrustedDirectory(root, "")
	if err != nil || after.id != bound.id || after.owner != bound.owner {
		return errOrdinary
	}
	f.profilesRoot, f.profileBaselineRoot, f.profileBaseline = root, bound, baseline
	return nil
}
func (f *ordinaryFixture) captureProfile(token windows.Token) error {
	if !f.profileAbsentBefore {
		return errOrdinary
	}
	profile, err := token.GetUserProfileDirectory()
	if err != nil || !filepath.IsAbs(profile) || filepath.Clean(profile) != profile || strings.Contains(profile[2:], ":") {
		return errOrdinary
	}
	bound, err := ordinaryRegistryString(windows.HKEY_LOCAL_MACHINE, ordinaryProfileKey+"\\"+f.sid, "ProfileImagePath", true)
	if err != nil || !strings.EqualFold(profile, bound) {
		return errOrdinary
	}
	profiles, err := ordinaryRegistryString(windows.HKEY_LOCAL_MACHINE, ordinaryProfileKey, "ProfilesDirectory", true)
	if err != nil {
		return errOrdinary
	}
	var native [32768]uint16
	size := uint32(len(native))
	ok, _, _ := ordinaryUserenv.NewProc("GetProfilesDirectoryW").Call(uintptr(unsafe.Pointer(&native[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size == 0 || size > uint32(len(native)) || !strings.EqualFold(windows.UTF16ToString(native[:]), profiles) || !strings.EqualFold(filepath.Dir(profile), profiles) {
		return errOrdinary
	}
	if f.profileBaseline == nil || !strings.EqualFold(profiles, f.profilesRoot) {
		return errOrdinary
	}
	baselineRoot, err := ordinaryTrustedDirectory(profiles, "")
	if err != nil || baselineRoot.id != f.profileBaselineRoot.id || baselineRoot.owner != f.profileBaselineRoot.owner {
		return errOrdinary
	}
	if _, existed := f.profileBaseline[strings.ToLower(filepath.Base(profile))]; existed {
		return errOrdinary
	}
	// Record every native ancestry component; no reparse or foreign mutable
	// ancestor is accepted. Profile root identity/owner is recorded separately.
	var parents []ordinaryObject
	for current := profiles; ; current = filepath.Dir(current) {
		object, err := ordinaryTrustedDirectory(current, "")
		if err != nil {
			return errOrdinary
		}
		parents = append(parents, object)
		if filepath.Dir(current) == current {
			break
		}
	}
	object, err := ordinaryTrustedDirectory(profile, f.sid)
	if err != nil {
		return errOrdinary
	}
	for _, beforeID := range f.profileBaseline {
		if object.id == beforeID {
			return errOrdinary
		}
	}
	f.profile, f.profilesRoot, f.profileObject, f.profileParents = profile, profiles, object, parents
	f.profileCaptured = true
	return nil
}

// Verify the returned suspended process image before its first thread runs.
func (f *ordinaryFixture) verifyProcessImage() error {
	var name [32768]uint16
	size := uint32(len(name))
	if windows.QueryFullProcessImageName(f.process, 0, &name[0], &size) != nil || size == 0 || size >= uint32(len(name)) {
		return errOrdinary
	}
	actual := windows.UTF16ToString(name[:size])
	if !filepath.IsAbs(actual) || filepath.Clean(actual) != actual || !strings.EqualFold(actual, f.image) || len(f.objects) < 2 || !strings.EqualFold(f.objects[1].path, f.image) {
		return errOrdinary
	}
	handle, err := ordinarySameObject(f.objects[1], windows.GENERIC_READ)
	if err != nil {
		return errOrdinary
	}
	file := os.NewFile(uintptr(handle), f.image)
	digest := sha256.New()
	n, readErr := io.Copy(digest, io.LimitReader(file, (128<<20)+1))
	state, stateErr := ordinaryState(f.image, handle)
	closeErr := file.Close()
	if closeErr != nil {
		ordinaryCloseFailure = true
	}
	if readErr != nil || closeErr != nil || stateErr != nil || state.id != f.objects[1].id || state.owner != f.objects[1].owner || n < 1 || n > 128<<20 || !bytes.Equal(digest.Sum(nil), f.imageHash[:]) {
		return errOrdinary
	}
	probe, err := ordinarySameObject(f.objects[1], windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return errOrdinary
	}
	if !ordinaryClose(&probe) {
		return errOrdinary
	}
	return nil
}
func (f *ordinaryFixture) launch() error {
	var desktop string
	if err := f.check("private-windowstation-desktop", func() error {
		var err error
		desktop, err = f.privateDesktop()
		return err
	}); err != nil {
		clear(f.password)
		return err
	}
	image, _ := windows.UTF16PtrFromString(f.image)
	cwd, _ := windows.UTF16PtrFromString(f.root)
	desktopUTF, _ := windows.UTF16PtrFromString(desktop)
	// Credentials never enter this command line, environment or diagnostics.
	workerArgument := ordinaryWorkerArgument
	if f.commands {
		workerArgument = ordinaryCommandWorkerArgument
	}
	command, _ := windows.UTF16FromString(syscall.EscapeArg(f.image) + " " + workerArgument + " " + strconv.Itoa(os.Getpid()))
	domain := []uint16{'.', 0}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktopUTF, Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE}
	var process windows.ProcessInformation
	ok, _, _ := ordinaryAdvapi.NewProc("CreateProcessWithLogonW").Call(
		uintptr(unsafe.Pointer(&f.account[0])), uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&f.password[0])), 1,
		uintptr(unsafe.Pointer(image)), uintptr(unsafe.Pointer(&command[0])), uintptr(windows.CREATE_SUSPENDED|windows.CREATE_NEW_CONSOLE),
		0, uintptr(unsafe.Pointer(cwd)), uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&process)))
	runtime.KeepAlive(f.password)
	clear(f.password)
	f.password = nil
	if process.Process != 0 {
		f.process = process.Process
		f.thread = process.Thread
		f.pid = process.ProcessId
	}
	if ok == 0 || f.process == 0 || f.thread == 0 || f.pid == 0 {
		return errOrdinary
	}
	var token windows.Token
	if windows.OpenProcessToken(f.process, windows.TOKEN_QUERY, &token) != nil {
		return errOrdinary
	}
	tokenErr := f.check("suspended-primary-token", func() error {
		if !ordinaryToken(token, f.sid, false) || f.sid == f.setupSID {
			return errOrdinary
		}
		var processMachine, nativeMachine uint16
		expected := map[string]uint16{"amd64": 0x8664, "arm64": 0xaa64}[runtime.GOARCH]
		if windows.IsWow64Process2(f.process, &processMachine, &nativeMachine) != nil || processMachine != 0 || nativeMachine != expected {
			return errOrdinary
		}
		return f.verifyProcessImage()
	})
	if tokenErr == nil {
		tokenErr = f.check("bound-loaded-profile", func() error { return f.captureProfile(token) })
	}
	closeErr := token.Close()
	if tokenErr != nil || closeErr != nil {
		return errOrdinary
	}
	if err := f.check("held-job-before-resume", func() error {
		var err error
		f.job, err = windows.CreateJobObject(nil, nil)
		if err != nil {
			return errOrdinary
		}
		limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(f.job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
			return errOrdinary
		}
		if windows.AssignProcessToJobObject(f.job, f.process) != nil {
			return errOrdinary
		}
		f.jobAssigned = true
		var accounting ordinaryAccounting
		if windows.QueryInformationJobObject(f.job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil) != nil || accounting.Active != 1 || accounting.Total != 1 {
			return errOrdinary
		}
		return nil
	}); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x00120183;;;" + f.sid + ")")
	if err != nil {
		return errOrdinary
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(ordinaryPipeName(uint32(os.Getpid()), f.pid))
	f.pipe, err = windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 256, 256, 0, &sa)
	runtime.KeepAlive(sd)
	if err != nil {
		return errOrdinary
	}
	if count, err := windows.ResumeThread(f.thread); err != nil || count != 1 {
		return errOrdinary
	}
	return nil
}
func ordinaryPipeName(parent, child uint32) string {
	return "\\\\.\\pipe\\AccessWeaverOrdinary-v1-" + strconv.FormatUint(uint64(parent), 10) + "-" + strconv.FormatUint(uint64(child), 10)
}

// Every operation owns a separate event, OVERLAPPED and backing buffer until
// kernel completion. CancelIoEx only requests cancellation.
func ordinaryPipeIO(pipe windows.Handle, operation string, buffer []byte, timeout time.Duration) (failure error) {
	pending := &ordinaryPending{buffer: buffer}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return errOrdinary
	}
	pending.event = event
	pending.overlap.HEvent = event
	pending.pin.Pin(&pending.overlap)
	if len(pending.buffer) > 0 {
		pending.pin.Pin(&pending.buffer[0])
	}
	completed := false
	defer func() {
		runtime.KeepAlive(pending)
		if completed {
			pending.pin.Unpin()
			if !ordinaryClose(&pending.event) {
				failure = errOrdinary
			}
		} else {
			ordinaryUnfinishedIO = append(ordinaryUnfinishedIO, pending)
			failure = errOrdinary
		}
	}()
	var done uint32
	switch operation {
	case "connect":
		err = windows.ConnectNamedPipe(pipe, &pending.overlap)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			completed = true
			return nil
		}
	case "read":
		err = windows.ReadFile(pipe, pending.buffer, &done, &pending.overlap)
	case "write":
		err = windows.WriteFile(pipe, pending.buffer, &done, &pending.overlap)
	default:
		completed = true
		return errOrdinary
	}
	if err == nil {
		resultErr := windows.GetOverlappedResult(pipe, &pending.overlap, &done, false)
		completed = !errors.Is(resultErr, windows.ERROR_IO_INCOMPLETE)
		if resultErr != nil || (operation != "connect" && done != uint32(len(buffer))) {
			return errOrdinary
		}
		return nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		completed = true
		return errOrdinary
	}
	wait, waitErr := windows.WaitForSingleObject(event, uint32(timeout/time.Millisecond))
	if waitErr != nil || wait != windows.WAIT_OBJECT_0 {
		_ = windows.CancelIoEx(pipe, &pending.overlap)
		// ERROR_NOT_FOUND can mean completion won the cancellation race.
		ended, endErr := windows.WaitForSingleObject(event, 5000)
		if endErr == nil && ended == windows.WAIT_OBJECT_0 {
			resultErr := windows.GetOverlappedResult(pipe, &pending.overlap, &done, false)
			completed = !errors.Is(resultErr, windows.ERROR_IO_INCOMPLETE)
		}
		return errOrdinary
	}
	err = windows.GetOverlappedResult(pipe, &pending.overlap, &done, false)
	completed = !errors.Is(err, windows.ERROR_IO_INCOMPLETE)
	if err != nil || (operation != "connect" && done != uint32(len(buffer))) {
		return errOrdinary
	}
	return nil
}
func (f *ordinaryFixture) exchange() error {
	return f.check("pid-bound-pipe", func() error {
		if ordinaryPipeIO(f.pipe, "connect", nil, 20*time.Second) != nil {
			return errOrdinary
		}
		var client uint32
		if windows.GetNamedPipeClientProcessId(f.pipe, &client) != nil || client != f.pid {
			return errOrdinary
		}
		request := make([]byte, 136)
		copy(request, ordinaryMagic[:])
		if _, err := rand.Read(request[8:40]); err != nil {
			return errOrdinary
		}
		copy(request[40:72], f.imageHash[:])
		copy(request[72:], os.Getenv("GITHUB_SHA"))
		if ordinaryPipeIO(f.pipe, "write", request, 20*time.Second) != nil {
			return errOrdinary
		}
		replySize, budget := ordinaryReplySize, 20*time.Second
		if f.commands {
			replySize++
			budget = 120 * time.Second
		}
		reply := make([]byte, replySize)
		if ordinaryPipeIO(f.pipe, "read", reply, budget) != nil || !bytes.Equal(reply[:8], ordinaryMagic[:]) || !bytes.Equal(reply[8:40], request[8:40]) {
			return errOrdinary
		}
		executed, passed := binary.LittleEndian.Uint64(reply[40:48]), binary.LittleEndian.Uint64(reply[48:56])
		expectedMask := uint64(31)
		if f.commands {
			expectedMask |= ((1 << len(ordinaryCommandCaseNames)) - 1) << 5
		}
		if executed&^expectedMask != 0 || passed&^executed != 0 {
			return errOrdinary
		}
		names := []string{"worker-primary-token", "worker-loaded-profile-hkcu", "worker-native-image", "worker-isolated-console-interrupt", "worker-public-recording-support-contract"}
		if f.commands {
			names = append(names, ordinaryCommandCaseNames...)
			stage := windowsDesktopStage(reply[ordinaryReplySize])
			const desktopCase = uint64(1) << (5 + 2)
			const capacityCase = uint64(1) << (5 + 6)
			failed := executed &^ passed
			if int(stage) >= len(windowsDesktopStageNames) ||
				(stage == windowsDesktopNoFailure && failed&desktopCase != 0) ||
				(stage != windowsDesktopNoFailure && failed&(desktopCase|capacityCase) == 0) {
				return errOrdinary
			}
			f.desktopFailure = stage
		}
		var failure error
		for bit, id := range names {
			if executed&(1<<bit) == 0 {
				failure = errOrdinary
				continue
			}
			if f.check(id, func() error {
				if passed&(1<<bit) == 0 {
					return errOrdinary
				}
				return nil
			}) != nil {
				failure = errOrdinary
			}
		}
		return failure
	})
}
func ordinaryHKCU(sid string) (valid bool) {
	var key windows.Handle
	code, _, _ := ordinaryAdvapi.NewProc("RegOpenCurrentUser").Call(uintptr(windows.KEY_READ), uintptr(unsafe.Pointer(&key)))
	if code != 0 || key == 0 {
		return false
	}
	defer func() {
		if windows.RegCloseKey(key) != nil {
			ordinaryCloseFailure = true
			valid = false
		}
	}()
	// Query the native KeyNameInformation name. The returned name is
	// length-delimited UTF-16, not NUL terminated. No registry marker is written.
	buffer := make([]byte, 2048)
	var size uint32
	status, _, _ := ordinaryNT.NewProc("NtQueryKey").Call(uintptr(key), 3, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&size)))
	if status != 0 || size < 4 || size > uint32(len(buffer)) {
		return false
	}
	length := binary.LittleEndian.Uint32(buffer[:4])
	if length%2 != 0 || length+4 > size {
		return false
	}
	name := unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[4])), int(length/2))
	return strings.EqualFold(windows.UTF16ToString(name), "\\REGISTRY\\USER\\"+sid)
}
func ordinaryWorkerProfile(token windows.Token, sid string) bool {
	profile, err := token.GetUserProfileDirectory()
	if err != nil || !ordinaryHKCU(sid) {
		return false
	}
	var flags uint32
	ok, _, _ := ordinaryUserenv.NewProc("GetProfileType").Call(uintptr(unsafe.Pointer(&flags)))
	if ok == 0 || flags != 0 {
		return false
	} // Require an already-loaded local profile.
	for _, item := range []struct {
		id          *windows.KNOWNFOLDERID
		environment string
	}{
		{windows.FOLDERID_Profile, "USERPROFILE"}, {windows.FOLDERID_RoamingAppData, "APPDATA"}, {windows.FOLDERID_LocalAppData, "LOCALAPPDATA"},
	} {
		path, err := windows.KnownFolderPath(item.id, 0)
		if err != nil || !strings.EqualFold(filepath.Clean(os.Getenv(item.environment)), path) || !filepath.IsAbs(path) || (path != profile && !strings.HasPrefix(strings.ToLower(path), strings.ToLower(profile)+"\\")) {
			return false
		}
		for current := path; ; current = filepath.Dir(current) {
			if _, err := ordinaryTrustedDirectory(current, sid); err != nil {
				return false
			}
			if filepath.Dir(current) == current {
				break
			}
		}
	}
	cache, err := os.UserCacheDir()
	local, localErr := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	return err == nil && localErr == nil && strings.EqualFold(cache, local)
}
func ordinaryConsoleInterrupt() bool {
	var processes [4]uint32
	count, _, _ := ordinaryKernel.NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&processes[0])), uintptr(len(processes)))
	if count != 1 || processes[0] != uint32(os.Getpid()) {
		return false
	}
	station, _, _ := ordinaryUser32.NewProc("GetProcessWindowStation").Call()
	if station == 0 {
		return false
	}
	var flags struct {
		Inherit, Reserved int32
		Flags             uint32
	}
	var size uint32
	ok, _, _ := ordinaryUser32.NewProc("GetUserObjectInformationW").Call(station, 1, uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Sizeof(flags)), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size != uint32(unsafe.Sizeof(flags)) || flags.Flags&1 != 0 {
		return false
	} // WSF_VISIBLE
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, 0) != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}
func runOrdinaryWindowsWorker(arguments []string, commands bool) (exitCode int) {
	if len(arguments) != 1 || !ordinaryNative() {
		return 91
	}
	parent, err := strconv.ParseUint(arguments[0], 10, 32)
	if err != nil || parent == 0 || uint32(parent) == uint32(os.Getpid()) {
		return 91
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !ordinaryNoImpersonation() {
		return 92
	}
	name, _ := windows.UTF16PtrFromString(ordinaryPipeName(uint32(parent), uint32(os.Getpid())))
	pipe, err := windows.CreateFile(name, ordinaryPipeAccess, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return 93
	}
	exitCode = 0
	defer func() {
		if windows.CloseHandle(pipe) != nil {
			exitCode = 96
		}
	}()
	var server uint32
	if windows.GetNamedPipeServerProcessId(pipe, &server) != nil || server != uint32(parent) {
		return 93
	}
	mode := uint32(windows.PIPE_READMODE_MESSAGE)
	if windows.SetNamedPipeHandleState(pipe, &mode, nil, nil) != nil {
		return 93
	}
	request := make([]byte, 136)
	if ordinaryPipeIO(pipe, "read", request, 20*time.Second) != nil || !bytes.Equal(request[:8], ordinaryMagic[:]) {
		return 94
	}
	var flags uint64
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
		return 95
	}
	user, userErr := token.GetTokenUser()
	if userErr == nil && user != nil && user.User.Sid != nil {
		sid := user.User.Sid.String()
		if ordinaryToken(token, sid, false) && ordinaryNoImpersonation() && uiaccess.RequireUnelevated() == nil {
			flags |= 1
		}
		if ordinaryWorkerProfile(token, sid) {
			flags |= 2
		}
	}
	if token.Close() != nil {
		return 95
	}
	executable, err := os.Executable()
	if err == nil {
		digest, err := ordinaryImageHash(executable)
		if err == nil && bytes.Equal(digest[:], request[40:72]) {
			flags |= 4
		}
	}
	if ordinaryConsoleInterrupt() {
		flags |= 8
	}
	var output bytes.Buffer
	_, initializeErr := audit.InitializeLocalJournal("")
	journal, openErr := audit.OpenLocalJournal(context.Background(), "", audit.Checkpoint{}, audit.Checkpoint{})
	exportErr := audit.ExportLocalSegment(context.Background(), "", audit.Checkpoint{}, audit.Checkpoint{}, &output)
	commandErr := auditInitializeCommand([]string{"initialize", "--directory", "INVALID-PRIVATE-DIRECTORY"}, &output)
	linked := buildinfo.Current()
	expectedCommit := strings.TrimRight(string(request[72:136]), "\x00")
	if audit.LocalRecordingSupported() && initializeErr != nil && !errors.Is(initializeErr, audit.ErrLocalStorageUnsupported) && journal == nil && openErr != nil && !errors.Is(openErr, audit.ErrLocalStorageUnsupported) && exportErr != nil && !errors.Is(exportErr, audit.ErrLocalStorageUnsupported) && commandErr != nil && output.Len() == 0 && linked.Commit == expectedCommit && linked.SourceState == "clean" {
		flags |= 16
	}
	executed := uint64(31)
	stage := windowsDesktopNoFailure
	if commands && flags == 31 {
		commandExecuted, commandPassed, desktopFailure := runWindowsCommandCases(request[8:40])
		executed |= commandExecuted << 5
		flags |= commandPassed << 5
		stage = desktopFailure
	}
	reply := make([]byte, ordinaryReplySize)
	if commands {
		reply = append(reply, byte(stage))
	}
	copy(reply, request[:40])
	binary.LittleEndian.PutUint64(reply[40:48], executed)
	binary.LittleEndian.PutUint64(reply[48:56], flags)
	if ordinaryPipeIO(pipe, "write", reply, 20*time.Second) != nil {
		return 96
	}
	expectedMask := uint64(31)
	if commands {
		expectedMask |= ((1 << len(ordinaryCommandCaseNames)) - 1) << 5
	}
	if flags != expectedMask || executed != expectedMask || len(ordinaryUnfinishedIO) != 0 || ordinaryCloseFailure {
		exitCode = 97
	}
	return exitCode
}

func (f *ordinaryFixture) finish() {
	clear(f.password)
	f.password = nil
	f.handlesClosed = true
	f.guiClosed = true
	f.processesEmpty = f.process == 0
	if f.process != 0 {
		f.check("worker-exit", func() error {
			status, err := windows.WaitForSingleObject(f.process, 20000)
			if err != nil || status != windows.WAIT_OBJECT_0 {
				if f.jobAssigned {
					_ = windows.TerminateJobObject(f.job, 98)
				} else {
					_ = windows.TerminateProcess(f.process, 98)
				}
				status, err = windows.WaitForSingleObject(f.process, 5000)
			}
			if err != nil || status != windows.WAIT_OBJECT_0 {
				f.cleanupOK = false
				return errOrdinary
			}
			f.processExited = true
			var code uint32
			if windows.GetExitCodeProcess(f.process, &code) != nil || code != 0 {
				return errOrdinary
			}
			return nil
		})
	}
	if !ordinaryClose(&f.thread) {
		f.handlesClosed = false
	}
	if !ordinaryClose(&f.process) {
		f.handlesClosed = false
	}
	if !ordinaryClose(&f.pipe) {
		f.handlesClosed = false
	}
	if f.jobAssigned {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var accounting ordinaryAccounting
			if windows.QueryInformationJobObject(f.job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil) != nil {
				break
			}
			if accounting.Active == 0 {
				f.processesEmpty = true
				break
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	} else if f.processExited {
		f.processesEmpty = true
	}
	if !ordinaryClose(&f.job) {
		f.handlesClosed = false
	}
	if !f.processesEmpty {
		f.cleanupOK = false
	}
	f.privateChildRemoved = true
	if f.childSlot != "" {
		entries, err := os.ReadDir(f.childSlot)
		f.privateChildRemoved = err == nil && len(entries) == 0
		if f.commands {
			for _, result := range f.cases {
				for _, id := range ordinaryCommandCaseNames {
					if result.ID == id && (!result.Executed || !result.Passed) {
						f.privateChildRemoved = false
					}
				}
			}
		}
		if !f.privateChildRemoved {
			f.cleanupOK = false
		}
	}
	f.policyRemoved = true
	if f.cleanupPolicy != nil {
		if !f.processesEmpty || f.cleanupPolicy() != nil {
			f.policyRemoved = false
			f.cleanupOK = false
		}
	}
	// LOGON_WITH_PROFILE has no owned PROFILEINFO.hProfile to unload. Wait for
	// the service's hive reference to disappear; never force-unload a user hive.
	if f.sid != "" {
		deadline := time.Now().Add(30 * time.Second)
		for !ordinaryRegistryAbsent(windows.HKEY_USERS, f.sid) || !ordinaryRegistryAbsent(windows.HKEY_USERS, f.sid+"_Classes") {
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		unloaded := ordinaryRegistryAbsent(windows.HKEY_USERS, f.sid) && ordinaryRegistryAbsent(windows.HKEY_USERS, f.sid+"_Classes")
		if f.profileCaptured && f.processesEmpty && f.privateChildRemoved && unloaded {
			actualSID, sidErr := ordinaryAccountSID(f.account)
			bound, pathErr := ordinaryRegistryString(windows.HKEY_LOCAL_MACHINE, ordinaryProfileKey+"\\"+f.sid, "ProfileImagePath", true)
			safe := sidErr == nil && actualSID == f.sid && pathErr == nil && strings.EqualFold(bound, f.profile) && strings.EqualFold(filepath.Dir(bound), f.profilesRoot)
			for _, parent := range f.profileParents {
				current, err := ordinaryTrustedDirectory(parent.path, "")
				if err != nil || current.id != parent.id || current.owner != parent.owner {
					safe = false
				}
			}
			current, err := ordinaryTrustedDirectory(f.profile, f.sid)
			if err != nil || current.id != f.profileObject.id || current.owner != f.profileObject.owner {
				safe = false
			}
			if safe {
				sid, _ := windows.UTF16PtrFromString(f.sid)
				path, _ := windows.UTF16PtrFromString(f.profile)
				ok, _, _ := ordinaryUserenv.NewProc("DeleteProfileW").Call(uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(path)), 0)
				if ok != 0 {
					_, absent := fileidentity.FromPath(f.profile, false)
					f.profileRemoved = errors.Is(absent, os.ErrNotExist) && ordinaryRegistryAbsent(windows.HKEY_LOCAL_MACHINE, ordinaryProfileKey+"\\"+f.sid) && ordinaryRegistryAbsent(windows.HKEY_USERS, f.sid) && ordinaryRegistryAbsent(windows.HKEY_USERS, f.sid+"_Classes")
				}
			}
		} else if !f.profileCaptured {
			// Failed launch can leave ambiguous service-created state. Absence must be
			// proved; do not adopt a newly observed profile and delete it by guessing.
			f.profileRemoved = unloaded && ordinaryRegistryAbsent(windows.HKEY_LOCAL_MACHINE, ordinaryProfileKey+"\\"+f.sid)
		}
		if !f.profileRemoved {
			f.cleanupOK = false
		}
	} else {
		f.profileRemoved = !f.accountCreated
	}
	if f.accountCreated {
		if f.profileRemoved && f.processesEmpty && f.privateChildRemoved {
			actual, err := ordinaryAccountSID(f.account)
			if err == nil && f.sid != "" && actual == f.sid {
				status, _, _ := ordinaryNet.NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(&f.account[0])))
				if status == 0 {
					var buffer *byte
					err := windows.NetUserGetInfo(nil, &f.account[0], 23, &buffer)
					freed := true
					if buffer != nil {
						freed = windows.NetApiBufferFree(buffer) == nil
					}
					f.accountRemoved = errors.Is(err, syscall.Errno(2221)) && freed
				}
			}
		}
		if !f.accountRemoved {
			f.cleanupOK = false
		}
	} else {
		f.accountRemoved = true
	}
	clear(f.account)
	if f.processesEmpty {
		if f.desktop != 0 {
			ok, _, _ := ordinaryUser32.NewProc("CloseDesktop").Call(uintptr(f.desktop))
			if ok == 0 {
				f.guiClosed = false
			}
			f.desktop = 0
		}
		if f.station != 0 {
			ok, _, _ := ordinaryUser32.NewProc("CloseWindowStation").Call(uintptr(f.station))
			if ok == 0 {
				f.guiClosed = false
			}
			f.station = 0
		}
	} else {
		f.guiClosed = false
	}
	f.stagingRemoved = true
	for index := len(f.objects) - 1; index >= 0; index-- {
		object := f.objects[index]
		safe := f.processesEmpty && (object.path == f.root || strings.EqualFold(filepath.Dir(object.path), f.root))
		if len(f.objects) > 0 {
			rootHandle, err := ordinarySameObject(f.objects[0], windows.FILE_READ_ATTRIBUTES)
			if err != nil {
				safe = false
			} else if !ordinaryClose(&rootHandle) {
				safe = false
				f.handlesClosed = false
			}
		}
		if !safe {
			f.stagingRemoved = false
			continue
		}
		handle, err := ordinarySameObject(object, windows.DELETE)
		if err != nil {
			f.stagingRemoved = false
			continue
		}
		remove := byte(1)
		if windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &remove, 1) != nil {
			f.stagingRemoved = false
		}
		if !ordinaryClose(&handle) {
			f.handlesClosed = false
			f.stagingRemoved = false
		}
		_, err = fileidentity.FromPath(object.path, false)
		if !errors.Is(err, os.ErrNotExist) {
			f.stagingRemoved = false
		}
	}
	if f.stagingCreated {
		_, absenceErr := fileidentity.FromPath(f.root, false)
		if !errors.Is(absenceErr, os.ErrNotExist) {
			f.stagingRemoved = false
		}
	}
	if len(ordinaryUnfinishedIO) != 0 || ordinaryCloseFailure {
		f.handlesClosed = false
	}
	if !f.handlesClosed || !f.guiClosed || !f.stagingRemoved {
		f.cleanupOK = false
	}
	f.check("exact-owned-cleanup", func() error {
		if !f.cleanupOK {
			return errOrdinary
		}
		return nil
	})
}
func ordinaryPublicMetadata(value string) string {
	if len(value) > 128 || strings.Trim(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._- ") != "" {
		return ""
	}
	return value
}
func (f *ordinaryFixture) report(t *testing.T) {
	t.Helper()
	if !f.cleanupOK {
		t.Error("ordinary Windows fixture cleanup incomplete; unknown objects preserved")
	}
	passed := !t.Failed() && f.cleanupOK
	for _, result := range f.cases {
		if !result.Executed || !result.Passed {
			t.Errorf("ordinary Windows fixture case failed: %s", result.ID)
			passed = false
		}
	}
	version := windows.RtlGetVersion()
	sourceCommit := os.Getenv("GITHUB_SHA")
	sourceBytes, sourceErr := hex.DecodeString(sourceCommit)
	if sourceErr != nil || (len(sourceBytes) != 20 && len(sourceBytes) != 32) || strings.ToLower(sourceCommit) != sourceCommit {
		sourceCommit = ""
	}
	runID, runAttempt := os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT")
	if !ordinaryDigits(runID) {
		runID = ""
	}
	if !ordinaryDigits(runAttempt) {
		runAttempt = ""
	}
	receiptName, scope := "ordinary", "native-ordinary-process-launch-profile-public-backend-supported"
	if f.commands {
		receiptName, scope = "commands", "native-ordinary-windows-audit-commands-required-policy"
	}
	report := map[string]any{
		"schemaVersion": 1, "scope": scope,
		"sourceCommit": sourceCommit, "githubRunID": runID, "githubRunAttempt": runAttempt,
		"goVersion": runtime.Version(), "platform": runtime.GOOS, "arch": runtime.GOARCH,
		"runnerArch": os.Getenv("RUNNER_ARCH"), "runnerEnvironment": os.Getenv("RUNNER_ENVIRONMENT"),
		"imageOS": ordinaryPublicMetadata(os.Getenv("ImageOS")), "imageVersion": ordinaryPublicMetadata(os.Getenv("ImageVersion")),
		"osVersion":       strconv.FormatUint(uint64(version.MajorVersion), 10) + "." + strconv.FormatUint(uint64(version.MinorVersion), 10) + "." + strconv.FormatUint(uint64(version.BuildNumber), 10),
		"testImageSHA256": hex.EncodeToString(f.imageHash[:]), "workerImageSHA256": hex.EncodeToString(f.imageHash[:]),
		"backendEnabled": audit.LocalRecordingSupported(), "cases": f.cases,
		"accountCreated": f.accountCreated, "ordinaryUsersMembershipAdded": f.usersAdded, "accountRemoved": f.accountRemoved,
		"profileAbsentBeforeLaunch": f.profileAbsentBefore, "profileBoundBeforeResume": f.profileCaptured, "profileRemoved": f.profileRemoved,
		"ownedProcessesExited": f.processExited, "ownedJobActiveProcessesAtEnd": map[bool]int{true: 0, false: -1}[f.processesEmpty],
		"stagingRemoved": f.stagingRemoved, "privateDesktopObjectsClosed": f.guiClosed, "allHandlesClosed": f.handlesClosed,
		"privateChildWorkspaceRemoved": f.privateChildRemoved, "requiredAuditPolicyEnrolled": f.policyInstalled, "requiredAuditPolicyRemoved": f.policyRemoved,
		"cleanupComplete": f.cleanupOK, "passed": passed, "productionQualificationComplete": false,
	}
	if f.commands {
		report["schemaVersion"] = 2
		report["desktopFailureStage"] = windowsDesktopStageNames[f.desktopFailure]
	}
	data, err := json.MarshalIndent(report, "", "  ")
	workspace := os.Getenv("GITHUB_WORKSPACE")
	if err != nil || !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		t.Error("ordinary Windows receipt destination unavailable")
		return
	}
	folder := filepath.Join(workspace, "build", "windows-audit-ordinary-checks")
	if os.MkdirAll(folder, 0755) != nil {
		t.Error("ordinary Windows receipt directory unavailable")
		return
	}
	file, err := os.OpenFile(filepath.Join(folder, receiptName+"-"+runtime.GOARCH+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		t.Error("ordinary Windows receipt unavailable")
		return
	}
	n, writeErr := file.Write(append(data, '\n'))
	flushErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || n != len(data)+1 || flushErr != nil || closeErr != nil {
		t.Error("ordinary Windows receipt incomplete")
	}
}
func TestDisposableWindowsAuditOrdinaryProcess(t *testing.T) {
	if _, present := os.LookupEnv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_ORDINARY_TEST"); !present {
		t.Skip("explicit disposable hosted Windows fixture only")
	}
	f := &ordinaryFixture{cleanupOK: true}
	for _, id := range ordinaryCaseNames {
		f.cases = append(f.cases, ordinaryCase{ID: id})
	}
	t.Cleanup(func() { f.finish(); f.report(t) })
	if f.prepare() != nil {
		t.Fatal("ordinary Windows fixture preparation failed")
	}
	if f.launch() != nil {
		t.Fatal("ordinary Windows fixture launch failed")
	}
	if f.exchange() != nil {
		t.Fatal("ordinary Windows fixture worker qualification failed")
	}
}
