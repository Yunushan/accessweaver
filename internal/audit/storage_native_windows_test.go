//go:build windows && (amd64 || arm64)

package audit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Only explicitly opted-in source-built hosted fixtures use these account APIs.
// No installed product, service, firewall, logon policy or privilege is changed.
var nativeAuditNet = windows.NewLazySystemDLL("netapi32.dll")
var nativeAuditLogon = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")

// Native USER_INFO_1 and USER_INFO_23 layouts, with native pointer alignment on
// both qualified architectures. NetUserGetInfo owns its buffer until freed.
type nativeAuditUserInfo1 struct {
	name, password         *uint16
	passwordAge, privilege uint32
	home, comment          *uint16
	flags                  uint32
	script                 *uint16
}
type nativeAuditUserInfo23 struct {
	name, fullName, comment *uint16
	flags                   uint32
	sid                     *windows.SID
}
type nativeAuditCase struct {
	ID       string `json:"id"`
	Executed bool   `json:"executed"`
	Passed   bool   `json:"passed"`
}
type nativeAuditOwnedObject struct {
	path      string
	id        windowsAuditIdentity
	owner     string
	directory bool
}
type nativeAuditFixture struct {
	root, owner                 string
	objects                     []nativeAuditOwnedObject
	closers                     []func() error
	accountName                 []uint16
	accountSID                  string
	accountCreated              bool
	accountRemoved              bool
	usersMembershipAdded        bool
	cases                       []nativeAuditCase
	cleanupOK                   bool
	testImageHash               string
	reportName, scope           string
	crossAccountPrivacyVerified bool
}

func nativeAuditFailure(message string) error { return errors.New(message) }

func nativeAuditTokenElevation(token windows.Token) (bool, error) {
	var elevation, n uint32
	if windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), 4, &n) != nil || n != 4 {
		return false, nativeAuditFailure("token elevation query failed")
	}
	return elevation != 0, nil
}

func nativeAuditGroups(token windows.Token) (users, admin bool, failure error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false, false, nativeAuditFailure("token group query failed")
	}
	for _, group := range groups.AllGroups() {
		if group.Sid == nil || !group.Sid.IsValid() {
			return false, false, nativeAuditFailure("invalid token group")
		}
		sid := group.Sid.String()
		if sid == "S-1-5-32-544" {
			admin = true // Even a deny-only Administrators SID is unexpected here.
		}
		if sid == "S-1-5-32-545" && group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			users = true
		}
	}
	runtime.KeepAlive(groups)
	return users, admin, nil
}

// Caller skips only when its explicit opt-in is absent. A declared fixture must
// fail on any unavailable identity, host, SDK or authority precondition.
func nativeAuditHost() (string, error) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST") != "1" {
		return "", nativeAuditFailure("native storage fixture requires exact explicit opt-in")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" {
		return "", nativeAuditFailure("opted-in fixture requires declared GitHub-hosted Windows context")
	}
	arch := runtime.GOARCH
	machine := map[string]uint16{"amd64": 0x8664, "arm64": 0xaa64}[arch]
	var processMachine, nativeMachine uint16
	if machine == 0 || runtime.GOOS != "windows" || os.Getenv("ACCESSWEAVER_EXPECT_GOOS") != "windows" || os.Getenv("ACCESSWEAVER_EXPECT_GOARCH") != arch || windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine) != nil || processMachine != 0 || nativeMachine != machine {
		return "", nativeAuditFailure("fixture requires matching native AMD64 or ARM64 host and process")
	}
	if os.Getenv("RUNNER_ARCH") != map[string]string{"amd64": "X64", "arm64": "ARM64"}[arch] || os.Getenv("GO_VERSION") == "" || runtime.Version() != "go"+os.Getenv("GO_VERSION") || os.Getenv("GOTOOLCHAIN") != "local" {
		return "", nativeAuditFailure("fixture SDK or runner architecture differs from declared native target")
	}
	commit := os.Getenv("GITHUB_SHA")
	decoded, err := hex.DecodeString(commit)
	if err != nil || (len(decoded) != 20 && len(decoded) != 32) || strings.ToLower(commit) != commit {
		return "", nativeAuditFailure("fixture requires exact source commit")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if requireProcessTokenContext() != nil {
		return "", nativeAuditFailure("setup refuses impersonation")
	}
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
		return "", nativeAuditFailure("setup token open failed")
	}
	user, userErr := token.GetTokenUser()
	elevated, elevationErr := nativeAuditTokenElevation(token)
	_, admin, groupsErr := nativeAuditGroups(token)
	closeErr := token.Close()
	if userErr != nil || elevationErr != nil || groupsErr != nil || closeErr != nil || !elevated || !admin || user.User.Sid == nil || !user.User.Sid.IsValid() || user.User.Sid.String() == "S-1-5-18" {
		return "", nativeAuditFailure("disposable account setup requires a non-SYSTEM administrator")
	}
	return user.User.Sid.String(), nil
}

func nativeAuditRawOpen(path string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, nativeAuditFailure("fixture path encoding failed")
	}
	return windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func nativeAuditObjectState(h windows.Handle) (windowsAuditIdentity, string, error) {
	var identity struct {
		Volume uint64
		ID     [16]byte
	}
	if windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&identity)), uint32(unsafe.Sizeof(identity))) != nil || identity.ID == ([16]byte{}) {
		return windowsAuditIdentity{}, "", nativeAuditFailure("fixture identity query failed")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return windowsAuditIdentity{}, "", nativeAuditFailure("fixture owner query failed")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return windowsAuditIdentity{}, "", nativeAuditFailure("fixture owner is invalid")
	}
	value := owner.String()
	runtime.KeepAlive(sd)
	return windowsAuditIdentity{volume: identity.Volume, fileID: identity.ID}, value, nil
}

func (f *nativeAuditFixture) record(path string, directory bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil || len(absolute) < 3 || strings.Contains(absolute[2:], ":") || (absolute != f.root && !strings.HasPrefix(strings.ToLower(absolute), strings.ToLower(f.root)+`\`)) {
		f.cleanupOK = false
		return nativeAuditFailure("fixture object escaped owned root")
	}
	h, err := nativeAuditRawOpen(path, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		f.cleanupOK = false
		return nativeAuditFailure("created fixture object could not be identified")
	}
	id, owner, stateErr := nativeAuditObjectState(h)
	closeErr := windows.CloseHandle(h)
	if stateErr != nil || closeErr != nil {
		f.cleanupOK = false
		return nativeAuditFailure("created fixture identity or close failed")
	}
	f.objects = append(f.objects, nativeAuditOwnedObject{path, id, owner, directory})
	return nil
}

// A source test may deliberately remove its own registered object, for example
// to exercise key loss. Forget only after native no-follow observation proves
// absence; never silently adopt a replacement object for subsequent deletion.
func (f *nativeAuditFixture) forget(path string) error {
	h, err := nativeAuditRawOpen(path, windows.FILE_READ_ATTRIBUTES)
	if err == nil {
		_ = windows.CloseHandle(h)
		return nativeAuditFailure("cannot forget a fixture object that still exists")
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nativeAuditFailure("cannot establish removed fixture object absence")
	}
	for n := len(f.objects) - 1; n >= 0; n-- {
		if strings.EqualFold(f.objects[n].path, path) {
			f.objects = append(f.objects[:n], f.objects[n+1:]...)
			return nil
		}
	}
	return nativeAuditFailure("cannot forget an unregistered fixture object")
}

func (f *nativeAuditFixture) directory(path string) error {
	sd, err := windowsAuditSecurityDescriptor(f.owner, true)
	if err != nil {
		return nativeAuditFailure("fixture private descriptor failed")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nativeAuditFailure("fixture directory encoding failed")
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(name, &sa)
	runtime.KeepAlive(sd)
	if err != nil {
		return nativeAuditFailure("exclusive fixture directory creation failed")
	}
	return f.record(path, true)
}

// Never wrap this root in testing.TempDir: that method's automatic recursive
// cleanup would delete unexpected objects that our identity checks preserve.
// Register f.finish before calling createRoot so partial setup is also reported.
func (f *nativeAuditFixture) createRoot() error {
	programs, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return nativeAuditFailure("protected fixture parent unavailable")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nativeAuditFailure("fixture path randomness failed")
	}
	f.root = filepath.Join(programs, "AccessWeaverAuditTest-"+hex.EncodeToString(random[:]))
	return f.directory(f.root)
}

func (f *nativeAuditFixture) track(close func() error) func() error {
	closed := false
	wrapped := func() error {
		if closed {
			return nil
		}
		closed = true
		if close() != nil {
			f.cleanupOK = false
			return nativeAuditFailure("owned native handle close failed")
		}
		return nil
	}
	f.closers = append(f.closers, wrapped)
	return wrapped
}
func (f *nativeAuditFixture) closeAll() error {
	var failure error
	for n := len(f.closers) - 1; n >= 0; n-- {
		failure = errors.Join(failure, f.closers[n]())
	}
	f.closers = nil
	return failure
}
func (f *nativeAuditFixture) openDirectory(path string) (*windowsAuditDirectory, error) {
	d, err := openWindowsAuditDirectory(path)
	if err != nil {
		return nil, nativeAuditFailure("native private directory open failed")
	}
	f.track(d.Close)
	return d, nil
}
func (f *nativeAuditFixture) create(d *windowsAuditDirectory, name string, data []byte) (*os.File, error) {
	file, err := d.createRegular(name)
	if err != nil {
		return nil, nativeAuditFailure("exclusive native private file create failed")
	}
	f.track(file.Close)
	if err := f.record(filepath.Join(d.path, name), false); err != nil {
		return nil, err
	}
	// FileModeInformation is a native FILE_MODE_INFORMATION ULONG. Observe the
	// kernel handle mode, rather than merely mirroring the requested open flags.
	var mode uint32
	var ios windows.IO_STATUS_BLOCK
	if windows.NtQueryInformationFile(windows.Handle(file.Fd()), &ios, (*byte)(unsafe.Pointer(&mode)), 4, 16) != nil || mode&windows.FILE_WRITE_THROUGH == 0 {
		return nil, nativeAuditFailure("native writable handle lacks write-through mode")
	}
	n, err := file.Write(data)
	if err != nil || n != len(data) || windows.FlushFileBuffers(windows.Handle(file.Fd())) != nil {
		return nil, nativeAuditFailure("exact native write or FlushFileBuffers failed")
	}
	return file, nil
}

func (f *nativeAuditFixture) createClosed(d *windowsAuditDirectory, name string, data []byte) (windowsAuditFileState, error) {
	file, err := f.create(d, name, data)
	if err != nil {
		return windowsAuditFileState{}, err
	}
	closeFile := f.closers[len(f.closers)-1]
	state, err := d.fileState(file, name)
	closeErr := closeFile()
	if err != nil || closeErr != nil {
		return windowsAuditFileState{}, nativeAuditFailure("created private file state or close failed")
	}
	return state, nil
}

func nativeAuditTestImageHash() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", nativeAuditFailure("test image location unavailable")
	}
	image, err := os.Open(executable)
	if err != nil {
		return "", nativeAuditFailure("test image read unavailable")
	}
	digest := sha256.New()
	n, readErr := io.Copy(digest, io.LimitReader(image, (128<<20)+1))
	closeErr := image.Close()
	if readErr != nil || closeErr != nil || n < 1 || n > 128<<20 {
		return "", nativeAuditFailure("test image hashing failed")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func nativeAuditAccountSID(name []uint16) (string, error) {
	var buffer *byte
	if len(name) < 2 {
		return "", nativeAuditFailure("local fixture account SID query failed")
	}
	if err := windows.NetUserGetInfo(nil, &name[0], 23, &buffer); err != nil || buffer == nil {
		if buffer != nil {
			_ = windows.NetApiBufferFree(buffer)
		}
		return "", nativeAuditFailure("local fixture account SID query failed")
	}
	info := (*nativeAuditUserInfo23)(unsafe.Pointer(buffer))
	value := ""
	if info.sid != nil && info.sid.IsValid() {
		value = info.sid.String()
	}
	freeErr := windows.NetApiBufferFree(buffer)
	if value == "" || freeErr != nil {
		return "", nativeAuditFailure("local fixture account SID or buffer cleanup failed")
	}
	return value, nil
}

func (f *nativeAuditFixture) ordinaryUsersMembership() error {
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return nativeAuditFailure("ordinary Users SID query failed")
	}
	alias, _, _, err := usersSID.LookupAccount("")
	aliasName, encodeErr := windows.UTF16PtrFromString(alias)
	if err != nil || encodeErr != nil || alias == "" {
		return nativeAuditFailure("ordinary Users alias resolution failed")
	}
	var buffer *byte
	var entries, total uint32
	status, _, _ := nativeAuditNet.NewProc("NetUserGetLocalGroups").Call(0, uintptr(unsafe.Pointer(&f.accountName[0])), 0, 1, uintptr(unsafe.Pointer(&buffer)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&total)))
	if status != 0 || entries > 128 || entries > total || (entries > 0 && buffer == nil) {
		if buffer != nil {
			_ = windows.NetApiBufferFree(buffer)
		}
		return nativeAuditFailure("ordinary local group membership query failed")
	}
	member := false
	if entries > 0 {
		groups := unsafe.Slice((**uint16)(unsafe.Pointer(buffer)), int(entries))
		for _, name := range groups {
			if name == nil {
				_ = windows.NetApiBufferFree(buffer)
				return nativeAuditFailure("ordinary local group membership is invalid")
			}
			if strings.EqualFold(windows.UTF16PtrToString(name), alias) {
				member = true
			}
		}
	}
	if buffer != nil && windows.NetApiBufferFree(buffer) != nil {
		return nativeAuditFailure("ordinary local group query buffer cleanup failed")
	}
	if member {
		return nil
	}
	// A fresh normal account is not guaranteed to receive this group from
	// NetUserAdd. Add only the localized well-known Users alias before logon;
	// never alter logon rights, privileges, administrative roles or other users.
	accountSID, err := windows.StringToSid(f.accountSID)
	if err != nil {
		return nativeAuditFailure("created account SID could not be used for ordinary membership")
	}
	entry := struct{ SID *windows.SID }{accountSID}
	status, _, _ = nativeAuditNet.NewProc("NetLocalGroupAddMembers").Call(0, uintptr(unsafe.Pointer(aliasName)), 0, uintptr(unsafe.Pointer(&entry)), 1)
	runtime.KeepAlive(usersSID)
	runtime.KeepAlive(accountSID)
	if status != 0 {
		return nativeAuditFailure("ordinary Users membership failed")
	}
	f.usersMembershipAdded = true
	return nil
}

func (f *nativeAuditFixture) account() (windows.Token, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return 0, nativeAuditFailure("account randomness failed")
	}
	defer clear(random[:])
	f.accountName, _ = windows.UTF16FromString("awa" + hex.EncodeToString(random[:8]))
	// The password exists only in clearable buffers, never a command, string,
	// environment value, diagnostic or retained artifact.
	password := make([]uint16, 69)
	copy(password, []uint16{'A', 'a', '1', '!'})
	const digits = "0123456789abcdef"
	for i, b := range random {
		password[4+2*i] = uint16(digits[b>>4])
		password[5+2*i] = uint16(digits[b&15])
	}
	defer clear(password)
	info := nativeAuditUserInfo1{name: &f.accountName[0], password: &password[0], privilege: 1, flags: 0x0201}
	var parameter uint32
	status, _, _ := nativeAuditNet.NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(password)
	if status != 0 {
		return 0, nativeAuditFailure("disposable ordinary account creation failed")
	}
	f.accountCreated = true
	var err error
	f.accountSID, err = nativeAuditAccountSID(f.accountName)
	if err != nil || f.accountSID == f.owner {
		return 0, nativeAuditFailure("created account identity is unavailable or not distinct")
	}
	if err := f.ordinaryUsersMembership(); err != nil {
		return 0, err
	}
	logon := func() (windows.Token, error) {
		domain := []uint16{'.', 0}
		var token windows.Token
		ok, _, _ := nativeAuditLogon.Call(uintptr(unsafe.Pointer(&f.accountName[0])), uintptr(unsafe.Pointer(&domain[0])), uintptr(unsafe.Pointer(&password[0])), 2, 0, uintptr(unsafe.Pointer(&token)))
		runtime.KeepAlive(password)
		if ok == 0 || token == 0 {
			return 0, nativeAuditFailure("ordinary local account logon failed; no policy workaround attempted")
		}
		return token, nil
	}
	token, err := logon()
	if err != nil {
		return 0, err
	}
	f.track(token.Close)
	users, admin, err := nativeAuditGroups(token)
	if err != nil || !users || admin {
		return 0, nativeAuditFailure("created account lacks ordinary membership or has administrative authority")
	}
	user, err := token.GetTokenUser()
	elevated, elevationErr := nativeAuditTokenElevation(token)
	restricted, restrictionErr := token.IsRestricted()
	if err != nil || elevationErr != nil || restrictionErr != nil || elevated || restricted || user.User.Sid == nil || user.User.Sid.String() != f.accountSID || user.User.Sid.String() == f.owner {
		return 0, nativeAuditFailure("privacy token is not a genuine distinct ordinary account")
	}
	return token, nil
}

func nativeAuditSetDescriptor(path string, sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, ownerErr := sd.Owner()
	acl, _, aclErr := sd.DACL()
	if ownerErr != nil || aclErr != nil {
		return nativeAuditFailure("fixture descriptor extraction failed")
	}
	err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil)
	runtime.KeepAlive(sd)
	if err != nil {
		return nativeAuditFailure("fixture descriptor application failed")
	}
	return nil
}
func nativeAuditDescriptor(path string) (string, error) {
	h, err := nativeAuditRawOpen(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return "", nativeAuditFailure("fixture descriptor handle open failed")
	}
	sd, securityErr := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	closeErr := windows.CloseHandle(h)
	if securityErr != nil || closeErr != nil {
		return "", nativeAuditFailure("fixture descriptor read or close failed")
	}
	return sd.String(), nil
}

func (f *nativeAuditFixture) canary(data []byte) (string, error) {
	path := filepath.Join(f.root, "readable-control")
	sd, err := windows.SecurityDescriptorFromString("O:" + f.owner + "D:P(A;;FA;;;" + f.owner + ")(A;;FA;;;SY)(A;;FR;;;" + f.accountSID + ")")
	if err != nil {
		return "", nativeAuditFailure("canary descriptor failed")
	}
	name, _ := windows.UTF16PtrFromString(path)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return "", nativeAuditFailure("readable control creation failed")
	}
	var n uint32
	writeErr := windows.WriteFile(h, data, &n, nil)
	flushErr := windows.FlushFileBuffers(h)
	closeErr := windows.CloseHandle(h)
	if err := f.record(path, false); err != nil {
		return "", err
	}
	if writeErr != nil || n != uint32(len(data)) || flushErr != nil || closeErr != nil {
		return "", nativeAuditFailure("readable control write or close failed")
	}
	return path, nil
}

// A disposable goroutine owns impersonation. Failed restoration retires its
// locked OS thread, so the parent never performs cleanup in that token context.
// There are no testing calls inside the unsafe context and only fixed errors
// cross back. Successful reversion also verifies the original process SID.
func nativeAuditAsOther(token windows.Token, owner string, body func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		var failure error
		var original processPrincipal
		defer func() {
			if recover() != nil {
				failure = nativeAuditFailure("privacy probe panicked")
			}
			if !restored {
				if windows.RevertToSelf() != nil {
					failure = nativeAuditFailure("privacy thread restoration failed")
				} else {
					principal, err := currentProcessPrincipal()
					if err != nil || principal != original || principal.kind != "sid" || principal.value != owner {
						failure = nativeAuditFailure("restored privacy thread identity differs")
					} else {
						restored = true
					}
				}
			}
			if restored {
				runtime.UnlockOSThread()
			}
			result <- failure
		}()
		var err error
		original, err = currentProcessPrincipal()
		if err != nil || original.kind != "sid" || original.value != owner {
			failure = nativeAuditFailure("privacy thread original identity unavailable")
			return
		}
		var impersonation windows.Token
		if windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation) != nil {
			failure = nativeAuditFailure("ordinary impersonation token creation failed")
			return
		}
		defer func() {
			if impersonation.Close() != nil {
				failure = nativeAuditFailure("privacy impersonation token close failed")
			}
		}()
		if windows.SetThreadToken(nil, impersonation) != nil {
			failure = nativeAuditFailure("ordinary account impersonation failed")
			return
		}
		restored = false
		failure = body()
	}()
	return <-result
}

func nativeAuditReadAsOther(path string, expected []byte) error {
	h, err := nativeAuditRawOpen(path, windows.GENERIC_READ)
	if err != nil {
		return nativeAuditFailure("ordinary account could not open positive readable control")
	}
	data := make([]byte, len(expected)+1)
	defer clear(data)
	var n uint32
	readErr := windows.ReadFile(h, data, &n, nil)
	closeErr := windows.CloseHandle(h)
	if readErr != nil || closeErr != nil || n != uint32(len(expected)) || !bytes.Equal(data[:n], expected) {
		return nativeAuditFailure("ordinary account positive read differs")
	}
	return nil
}
func nativeAuditDeniedRead(path string) error {
	h, err := nativeAuditRawOpen(path, windows.GENERIC_READ)
	if err == nil {
		var one [1]byte
		var n uint32
		_ = windows.ReadFile(h, one[:], &n, nil)
		_ = windows.CloseHandle(h)
		clear(one[:])
		return nativeAuditFailure("different account opened private file for content reading")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nativeAuditFailure("privacy refusal was not native ACCESS_DENIED")
	}
	return nil
}

func (f *nativeAuditFixture) finish(t *testing.T) {
	t.Helper()
	if f.testImageHash == "" {
		var err error
		f.testImageHash, err = nativeAuditTestImageHash()
		if err != nil {
			t.Error("native fixture test image provenance unavailable")
		}
	}
	if f.closeAll() != nil {
		f.cleanupOK = false
	}
	if f.accountCreated {
		actual, err := nativeAuditAccountSID(f.accountName)
		if err != nil || f.accountSID == "" || actual != f.accountSID {
			f.cleanupOK = false
		} else {
			status, _, _ := nativeAuditNet.NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(&f.accountName[0])))
			if status != 0 {
				f.cleanupOK = false
			} else {
				var buffer *byte
				err := windows.NetUserGetInfo(nil, &f.accountName[0], 23, &buffer)
				if buffer != nil {
					_ = windows.NetApiBufferFree(buffer)
				}
				f.accountRemoved = errors.Is(err, syscall.Errno(2221)) // NERR_UserNotFound
				if !f.accountRemoved {
					f.cleanupOK = false
				}
			}
		}
	}
	clear(f.accountName)
	for n := len(f.objects) - 1; n >= 0; n-- {
		object := f.objects[n]
		absolute, err := filepath.Abs(object.path)
		if err != nil || (absolute != f.root && !strings.HasPrefix(strings.ToLower(absolute), strings.ToLower(f.root)+`\`)) {
			f.cleanupOK = false
			continue
		}
		h, err := nativeAuditRawOpen(object.path, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
		if err != nil {
			f.cleanupOK = false
			continue
		}
		id, owner, stateErr := nativeAuditObjectState(h)
		// Delete only through the exact checked handle. There is no recursive
		// traversal: replaced objects, changed owners and unowned contents stay.
		if stateErr != nil || id != object.id || owner != object.owner {
			f.cleanupOK = false
		} else {
			remove := byte(1)
			if windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &remove, 1) != nil {
				f.cleanupOK = false
			}
		}
		if windows.CloseHandle(h) != nil {
			f.cleanupOK = false
		}
		probe, err := nativeAuditRawOpen(object.path, windows.FILE_READ_ATTRIBUTES)
		if err == nil {
			_ = windows.CloseHandle(probe)
			f.cleanupOK = false
		} else if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			f.cleanupOK = false
		}
	}
	if !f.cleanupOK {
		t.Error("native fixture cleanup incomplete; no unowned object deletion attempted")
	}
	version := windows.RtlGetVersion()
	if f.reportName == "" {
		f.reportName = "native"
	}
	if f.scope == "" {
		f.scope = "native-storage-primitives-and-different-account-read-privacy"
	}
	report := map[string]any{
		"schemaVersion": 1, "sourceCommit": os.Getenv("GITHUB_SHA"), "goVersion": runtime.Version(),
		"platform": runtime.GOOS, "arch": runtime.GOARCH, "runnerArch": os.Getenv("RUNNER_ARCH"),
		"runnerEnvironment": os.Getenv("RUNNER_ENVIRONMENT"), "imageOS": os.Getenv("ImageOS"), "imageVersion": os.Getenv("ImageVersion"),
		"osVersion":       fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber),
		"testImageSHA256": f.testImageHash, "backendEnabled": LocalRecordingSupported(), "cases": f.cases,
		"cleanupComplete": f.cleanupOK, "accountCreated": f.accountCreated, "accountRemoved": f.accountRemoved,
		"ordinaryUsersMembershipAdded": f.usersMembershipAdded, "passed": !t.Failed() && f.cleanupOK,
		"crossAccountPrivacyVerified": f.crossAccountPrivacyVerified,
		"scope":                       f.scope, "productionQualificationComplete": false,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	folder := filepath.Join("build", "windows-audit-storage-checks")
	if err != nil || os.MkdirAll(folder, 0755) != nil || os.WriteFile(filepath.Join(folder, f.reportName+"-"+runtime.GOARCH+".json"), append(data, '\n'), 0644) != nil {
		t.Error("could not retain bounded native storage acceptance evidence")
	}
}

func TestDisposableWindowsAuditStorageNative(t *testing.T) {
	if _, present := os.LookupEnv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST"); !present {
		t.Skip("requires explicitly opted-in disposable hosted Windows source fixture")
	}
	f := &nativeAuditFixture{cleanupOK: true}
	for _, id := range []string{
		"native-host", "private-ntfs-roundtrip-write-through-flush", "exclusive-create-preserves-content",
		"no-delete-sharing-binding", "foreign-read-ace-refused-without-repair", "native-hardlink-refused",
		"native-reparse-file-and-directory-refused", "ads-name-refused-without-content-change",
		"real-other-account-read-privacy", "closed-directory-refuses-reuse",
	} {
		f.cases = append(f.cases, nativeAuditCase{ID: id})
	}
	t.Cleanup(func() { f.finish(t) })
	run := func(id string, body func() error) {
		t.Helper()
		for n := range f.cases {
			if f.cases[n].ID == id {
				f.cases[n].Executed = true
				if err := body(); err != nil {
					t.Fatal(err)
				}
				f.cases[n].Passed = true
				return
			}
		}
		t.Fatal("unknown fixed native case")
	}
	run("native-host", func() error {
		owner, err := nativeAuditHost()
		if err != nil {
			return err
		}
		f.owner = owner
		f.testImageHash, err = nativeAuditTestImageHash()
		if err != nil {
			return err
		}
		return f.createRoot()
	})
	key := make([]byte, actorKeyFileBytes)
	defer clear(key)
	copy(key, actorKeyPrefix)
	if _, err := rand.Read(key[len(actorKeyPrefix):]); err != nil {
		t.Fatal("fixture key randomness failed")
	}
	journal := []byte("native storage acceptance; no full journal qualification\n")
	var d *windowsAuditDirectory
	var keyState, journalState windowsAuditFileState
	run("private-ntfs-roundtrip-write-through-flush", func() error {
		var err error
		d, err = f.openDirectory(f.root)
		if err != nil {
			return err
		}
		keyState, err = f.createClosed(d, actorKeyName, key)
		if err != nil {
			return err
		}
		journalState, err = f.createClosed(d, journalName, journal)
		if err != nil || keyState.id == journalState.id || keyState.id.volume != journalState.id.volume || keyState.size != int64(len(key)) || journalState.size != int64(len(journal)) || keyState.links != 1 || journalState.links != 1 {
			return nativeAuditFailure("private native file identity, size or link count differs")
		}
		for _, item := range []struct {
			name  string
			state windowsAuditFileState
		}{{actorKeyName, keyState}, {journalName, journalState}} {
			id, exists, err := d.probeIdentity(item.name)
			if err != nil || !exists || id != item.state.id {
				return nativeAuditFailure("metadata probe differs from opened identity")
			}
		}
		if d.checkBinding() != nil || f.closeAll() != nil {
			return nativeAuditFailure("private binding or initial close failed")
		}
		d, err = f.openDirectory(f.root)
		if err != nil {
			return err
		}
		for _, item := range []struct {
			name  string
			data  []byte
			state windowsAuditFileState
		}{{actorKeyName, key, keyState}, {journalName, journal, journalState}} {
			file, err := d.openRegular(item.name, false)
			if err != nil {
				return nativeAuditFailure("closed private file could not reopen")
			}
			closeFile := f.track(file.Close)
			got, readErr := io.ReadAll(io.LimitReader(file, int64(len(item.data)+1)))
			state, stateErr := d.fileState(file, item.name)
			same := bytes.Equal(got, item.data)
			clear(got)
			if readErr != nil || stateErr != nil || state.id != item.state.id || !same || closeFile() != nil {
				return nativeAuditFailure("reopened private bytes or identities differ")
			}
		}
		return nil
	})
	run("exclusive-create-preserves-content", func() error {
		for _, item := range []struct {
			name string
			data []byte
		}{{actorKeyName, key}, {journalName, journal}} {
			file, err := d.createRegular(item.name)
			if file != nil {
				_ = file.Close()
				return nativeAuditFailure("exclusive create returned preexisting private file")
			}
			if !errors.Is(err, ErrJournalStorage) {
				return nativeAuditFailure("exclusive create did not refuse existing entry")
			}
			got, readErr := os.ReadFile(filepath.Join(f.root, item.name))
			same := bytes.Equal(got, item.data)
			clear(got)
			if readErr != nil || !same {
				return nativeAuditFailure("exclusive-create refusal changed bytes")
			}
		}
		return nil
	})
	run("no-delete-sharing-binding", func() error {
		file, err := d.openRegular(journalName, false)
		if err != nil {
			return nativeAuditFailure("binding probe file open failed")
		}
		closeFile := f.track(file.Close)
		defer closeFile()
		for _, path := range []string{f.root, filepath.Join(f.root, journalName)} {
			h, err := nativeAuditRawOpen(path, windows.DELETE)
			if err == nil {
				_ = windows.CloseHandle(h)
				return nativeAuditFailure("retained binding unexpectedly permits delete open")
			}
			if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				return nativeAuditFailure("binding exclusion was not a sharing violation")
			}
		}
		if d.checkBinding() != nil {
			return nativeAuditFailure("retained directory binding changed")
		}
		return nil
	})
	run("foreign-read-ace-refused-without-repair", func() error {
		path := filepath.Join(f.root, "foreign-read")
		if err := f.directory(path); err != nil {
			return err
		}
		foreign, err := f.openDirectory(path)
		if err != nil {
			return err
		}
		if _, err := f.createClosed(foreign, journalName, journal); err != nil {
			return err
		}
		filePath := filepath.Join(path, journalName)
		sd, err := windows.SecurityDescriptorFromString("O:" + f.owner + "D:P(A;;FA;;;" + f.owner + ")(A;;FA;;;SY)(A;;FR;;;BU)")
		if err != nil || nativeAuditSetDescriptor(filePath, sd) != nil {
			return nativeAuditFailure("real foreign-read ACE fixture setup failed")
		}
		before, err := nativeAuditDescriptor(filePath)
		if err != nil {
			return err
		}
		opened, openErr := foreign.openRegular(journalName, false)
		if opened != nil {
			_ = opened.Close()
			return nativeAuditFailure("foreign-read ACE was admitted")
		}
		if !errors.Is(openErr, ErrJournalStorage) {
			return nativeAuditFailure("foreign-read ACE did not produce storage refusal")
		}
		after, err := nativeAuditDescriptor(filePath)
		got, readErr := os.ReadFile(filePath)
		if err != nil || readErr != nil || before != after || !bytes.Equal(got, journal) {
			return nativeAuditFailure("foreign-ACE refusal repaired permissions or altered bytes")
		}
		return nil
	})
	run("native-hardlink-refused", func() error {
		path := filepath.Join(f.root, "hardlink")
		if err := f.directory(path); err != nil {
			return err
		}
		linked, err := f.openDirectory(path)
		if err != nil {
			return err
		}
		if _, err := f.createClosed(linked, journalName, journal); err != nil {
			return err
		}
		aliasPath := filepath.Join(path, "owned-alias")
		alias, _ := windows.UTF16PtrFromString(aliasPath)
		target, _ := windows.UTF16PtrFromString(filepath.Join(path, journalName))
		if windows.CreateHardLink(alias, target, 0) != nil {
			return nativeAuditFailure("native hardlink fixture creation failed")
		}
		if err := f.record(aliasPath, false); err != nil {
			return err
		}
		h, err := nativeAuditRawOpen(filepath.Join(path, journalName), windows.FILE_READ_ATTRIBUTES)
		if err != nil {
			return nativeAuditFailure("hardlink observation open failed")
		}
		var info windows.ByHandleFileInformation
		statErr := windows.GetFileInformationByHandle(h, &info)
		closeErr := windows.CloseHandle(h)
		if statErr != nil || closeErr != nil || info.NumberOfLinks != 2 {
			return nativeAuditFailure("native hardlink fixture lacks two links")
		}
		opened, err := linked.openRegular(journalName, false)
		if opened != nil {
			_ = opened.Close()
			return nativeAuditFailure("native hardlink was admitted")
		}
		if !errors.Is(err, ErrJournalStorage) {
			return nativeAuditFailure("native hardlink did not refuse")
		}
		got, err := os.ReadFile(filepath.Join(path, journalName))
		if err != nil || !bytes.Equal(got, journal) {
			return nativeAuditFailure("hardlink refusal changed content")
		}
		return nil
	})
	run("native-reparse-file-and-directory-refused", func() error {
		path := filepath.Join(f.root, "reparse")
		if err := f.directory(path); err != nil {
			return err
		}
		reparse, err := f.openDirectory(path)
		if err != nil {
			return err
		}
		linkPath := filepath.Join(path, journalName)
		link, _ := windows.UTF16PtrFromString(linkPath)
		target, _ := windows.UTF16PtrFromString(filepath.Join(f.root, journalName))
		if windows.CreateSymbolicLink(link, target, 0) != nil {
			return nativeAuditFailure("native file reparse fixture creation failed; no privilege workaround attempted")
		}
		if err := f.record(linkPath, false); err != nil {
			return err
		}
		opened, err := reparse.openRegular(journalName, false)
		if opened != nil {
			_ = opened.Close()
			return nativeAuditFailure("native file reparse point was followed")
		}
		if !errors.Is(err, ErrJournalStorage) {
			return nativeAuditFailure("native file reparse point did not refuse")
		}
		directoryPath := filepath.Join(f.root, "directory-reparse")
		directoryLink, _ := windows.UTF16PtrFromString(directoryPath)
		directoryTarget, _ := windows.UTF16PtrFromString(path)
		if windows.CreateSymbolicLink(directoryLink, directoryTarget, windows.SYMBOLIC_LINK_FLAG_DIRECTORY) != nil {
			return nativeAuditFailure("native directory reparse fixture creation failed; no privilege workaround attempted")
		}
		if err := f.record(directoryPath, true); err != nil {
			return err
		}
		aliased, err := openWindowsAuditDirectory(directoryPath)
		if aliased != nil {
			_ = aliased.Close()
			return nativeAuditFailure("native directory reparse point was followed")
		}
		if !errors.Is(err, ErrJournalStorage) {
			return nativeAuditFailure("native directory reparse point did not refuse")
		}
		got, err := os.ReadFile(filepath.Join(f.root, journalName))
		if err != nil || !bytes.Equal(got, journal) {
			return nativeAuditFailure("reparse refusal changed target content")
		}
		return nil
	})
	run("ads-name-refused-without-content-change", func() error {
		streamPath := filepath.Join(f.root, journalName) + ":owned-fixture"
		name, _ := windows.UTF16PtrFromString(streamPath)
		h, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			return nativeAuditFailure("native alternate stream fixture creation failed")
		}
		payload := []byte("inert alternate stream")
		var n uint32
		writeErr := windows.WriteFile(h, payload, &n, nil)
		closeErr := windows.CloseHandle(h)
		// The stream belongs to the already registered base-file identity. Exact
		// base-file deletion also removes its streams; do not double-register it.
		if writeErr != nil || closeErr != nil || n != uint32(len(payload)) {
			return nativeAuditFailure("native alternate stream write failed")
		}
		opened, err := d.openRegular(journalName+":owned-fixture", false)
		if opened != nil {
			_ = opened.Close()
			return nativeAuditFailure("alternate stream child name admitted")
		}
		if !errors.Is(err, ErrJournalStorage) {
			return nativeAuditFailure("alternate stream child name did not refuse")
		}
		got, streamErr := os.ReadFile(streamPath)
		base, baseErr := os.ReadFile(filepath.Join(f.root, journalName))
		if streamErr != nil || baseErr != nil || !bytes.Equal(got, payload) || !bytes.Equal(base, journal) {
			return nativeAuditFailure("alternate stream refusal changed protected content")
		}
		return nil
	})
	run("real-other-account-read-privacy", func() error {
		storageClosers := len(f.closers)
		token, err := f.account()
		if err != nil {
			return err
		}
		// Keep only the distinct account token alive. Privacy cannot be proved
		// by a sharing violation or a retained journal byte-range lock.
		for _, close := range f.closers[:storageClosers] {
			if close() != nil {
				return nativeAuditFailure("pre-privacy storage close failed")
			}
		}
		control := []byte("positive same-directory ordinary-account read")
		canary, err := f.canary(control)
		if err != nil {
			return err
		}
		beforeDescriptor, err := nativeAuditDescriptor(canary)
		if err != nil {
			return err
		}
		baseline, err := ProcessProducer(fixtureActorKey())
		if err != nil {
			return nativeAuditFailure("baseline process identity unavailable")
		}
		err = nativeAuditAsOther(token, f.owner, func() error {
			if err := nativeAuditReadAsOther(canary, control); err != nil {
				return err
			}
			for _, name := range []string{actorKeyName, journalName} {
				if err := nativeAuditDeniedRead(filepath.Join(f.root, name)); err != nil {
					return err
				}
			}
			producer, err := ProcessProducer(fixtureActorKey())
			if !errors.Is(err, ErrProcessIdentity) || producer != (Producer{}) {
				return nativeAuditFailure("production identity did not refuse distinct-account impersonation")
			}
			opened, err := openWindowsAuditDirectory(f.root)
			if opened != nil {
				_ = opened.Close()
				return nativeAuditFailure("production storage admitted impersonation")
			}
			if !errors.Is(err, ErrProcessIdentity) {
				return nativeAuditFailure("production storage impersonation refusal differs")
			}
			return nil
		})
		if err != nil {
			return err
		}
		after, identityErr := ProcessProducer(fixtureActorKey())
		afterDescriptor, descriptorErr := nativeAuditDescriptor(canary)
		canaryBytes, canaryErr := os.ReadFile(canary)
		keyBytes, keyErr := os.ReadFile(filepath.Join(f.root, actorKeyName))
		defer clear(keyBytes)
		journalBytes, journalErr := os.ReadFile(filepath.Join(f.root, journalName))
		if identityErr != nil || baseline != after || descriptorErr != nil || beforeDescriptor != afterDescriptor || canaryErr != nil || !bytes.Equal(canaryBytes, control) || keyErr != nil || !bytes.Equal(keyBytes, key) || journalErr != nil || !bytes.Equal(journalBytes, journal) {
			return nativeAuditFailure("restored identity, canary ownership or private content changed")
		}
		f.crossAccountPrivacyVerified = true
		return nil
	})
	run("closed-directory-refuses-reuse", func() error {
		if d.Close() != nil || d.Close() != nil {
			return nativeAuditFailure("directory close is not idempotent")
		}
		file, err := d.openRegular(journalName, false)
		if file != nil {
			_ = file.Close()
			return nativeAuditFailure("closed directory reused native handle")
		}
		if err == nil {
			return nativeAuditFailure("closed directory did not refuse reuse")
		}
		return nil
	})
}
