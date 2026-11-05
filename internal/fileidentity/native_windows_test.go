//go:build windows

package fileidentity

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func requireDisposableWindowsIdentityHost(t *testing.T) {
	t.Helper()
	value, present := os.LookupEnv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST")
	if !present {
		t.Skip("requires explicitly opted-in disposable hosted Windows source fixture")
	}
	if value != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Fatal("declared native identity fixture requires exact opt-in and GitHub-hosted Windows context")
	}
	arch := runtime.GOARCH
	machine := map[string]uint16{"amd64": 0x8664, "arm64": 0xaa64}[arch]
	var processMachine, nativeMachine uint16
	if machine == 0 || runtime.GOOS != "windows" || os.Getenv("ACCESSWEAVER_EXPECT_GOOS") != "windows" ||
		os.Getenv("ACCESSWEAVER_EXPECT_GOARCH") != arch || os.Getenv("RUNNER_ARCH") != map[string]string{"amd64": "X64", "arm64": "ARM64"}[arch] ||
		windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine) != nil || processMachine != 0 || nativeMachine != machine {
		t.Fatal("declared identity fixture requires a matching native host and process")
	}
	if os.Getenv("GO_VERSION") == "" || runtime.Version() != "go"+os.Getenv("GO_VERSION") || os.Getenv("GOTOOLCHAIN") != "local" {
		t.Fatal("declared native identity fixture SDK differs from expected local SDK")
	}
}

// Registered before TempDir so its cleanup runs after all fixture cleanup and
// records the final test state. This evidence qualifies this source-built test
// only; it does not grant publication or production readiness.
func reportDisposableWindowsIdentity(t *testing.T) {
	t.Helper()
	workspace := os.Getenv("GITHUB_WORKSPACE")
	absolute, absoluteErr := filepath.Abs(workspace)
	if workspace == "" || !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace || absoluteErr != nil || absolute != workspace {
		t.Error("native identity evidence requires an absolute canonical workspace")
		return
	}
	commit := os.Getenv("GITHUB_SHA")
	decoded, commitErr := hex.DecodeString(commit)
	if commitErr != nil || (len(decoded) != 20 && len(decoded) != 32) || strings.ToLower(commit) != commit {
		t.Error("native identity evidence requires an exact source commit")
		return
	}
	runID := os.Getenv("GITHUB_RUN_ID")
	run, runErr := strconv.ParseUint(runID, 10, 64)
	if runErr != nil || run == 0 || strconv.FormatUint(run, 10) != runID {
		t.Error("native identity evidence requires a canonical source run identifier")
		return
	}
	if os.Getenv("GO_VERSION") == "" || runtime.Version() != "go"+os.Getenv("GO_VERSION") || os.Getenv("GOTOOLCHAIN") != "local" {
		t.Error("native identity evidence requires the declared local SDK")
		return
	}
	imageOS, imageVersion := os.Getenv("ImageOS"), os.Getenv("ImageVersion")
	metadataText := func(value string) bool {
		if value == "" || len(value) > 128 {
			return false
		}
		for _, ch := range value {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '-' || ch == '_') {
				return false
			}
		}
		return true
	}
	if !metadataText(imageOS) || !metadataText(imageVersion) {
		t.Error("native identity evidence requires bounded runner image metadata")
		return
	}
	executable, executableErr := os.Executable()
	if executableErr != nil {
		t.Error("native identity evidence test image unavailable")
		return
	}
	image, openErr := os.Open(executable)
	if openErr != nil {
		t.Error("native identity evidence test image unavailable")
		return
	}
	const maximumImageBytes int64 = 128 << 20
	info, statErr := image.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumImageBytes {
		_ = image.Close()
		t.Error("native identity evidence test image exceeds its bound")
		return
	}
	digest := sha256.New()
	count, readErr := io.Copy(digest, io.LimitReader(image, maximumImageBytes+1))
	closeErr := image.Close()
	if readErr != nil || closeErr != nil || count != info.Size() || count > maximumImageBytes {
		t.Error("native identity evidence test image hash failed")
		return
	}
	report := struct {
		SchemaVersion                   int    `json:"schemaVersion"`
		SourceCommit                    string `json:"sourceCommit"`
		RunID                           string `json:"runID"`
		TestName                        string `json:"testName"`
		Platform                        string `json:"platform"`
		Arch                            string `json:"arch"`
		RuntimeGoVersion                string `json:"runtimeGoVersion"`
		RunnerArch                      string `json:"runnerArch"`
		RunnerEnvironment               string `json:"runnerEnvironment"`
		ImageOS                         string `json:"imageOS"`
		ImageVersion                    string `json:"imageVersion"`
		TestImageSHA256                 string `json:"testImageSHA256"`
		Passed                          bool   `json:"passed"`
		Scope                           string `json:"scope"`
		ProductionQualificationComplete bool   `json:"productionQualificationComplete"`
	}{
		SchemaVersion: 1, SourceCommit: commit, RunID: runID, TestName: t.Name(),
		Platform: runtime.GOOS, Arch: runtime.GOARCH, RuntimeGoVersion: runtime.Version(),
		RunnerArch: os.Getenv("RUNNER_ARCH"), RunnerEnvironment: os.Getenv("RUNNER_ENVIRONMENT"),
		ImageOS: imageOS, ImageVersion: imageVersion, TestImageSHA256: hex.EncodeToString(digest.Sum(nil)),
		Passed: !t.Failed(), Scope: "source-built-native-file-identity", ProductionQualificationComplete: false,
	}
	data, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr != nil || len(data) > 4096 {
		t.Error("native identity evidence encoding failed")
		return
	}
	folder := filepath.Join(workspace, "build", "windows-audit-identity-input-checks")
	if os.MkdirAll(folder, 0755) != nil || os.WriteFile(filepath.Join(folder, "fileidentity-"+runtime.GOARCH+".json"), append(data, '\n'), 0644) != nil {
		t.Error("native identity evidence could not be retained")
	}
}
func identityWindowsLink(t *testing.T, target, path string, directory bool) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("fixture link name conversion failed")
	}
	destination, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal("fixture link target conversion failed")
	}
	flags := uint32(0)
	if directory {
		flags = windows.SYMBOLIC_LINK_FLAG_DIRECTORY
	}
	// Direct creation does not stat or contact a remote target. No privilege
	// or account state is changed; fixture unavailability is a failure.
	if err := windows.CreateSymbolicLink(name, destination, flags|0x2); err != nil {
		if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) || windows.CreateSymbolicLink(name, destination, flags) != nil {
			t.Fatal("declared native fixture could not create a symlink")
		}
	}
}

func identityWindowsJunction(t *testing.T, target, path string) {
	t.Helper()
	if os.Mkdir(path, 0700) != nil {
		t.Fatal("fixture junction directory creation failed")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("fixture junction path unavailable")
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal("fixture junction handle unavailable")
	}
	defer windows.CloseHandle(handle)
	substitute, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		t.Fatal("fixture junction substitute unavailable")
	}
	printName, err := windows.UTF16FromString(target)
	if err != nil {
		t.Fatal("fixture junction print name unavailable")
	}
	data := make([]byte, 16+2*(len(substitute)+len(printName)))
	binary.LittleEndian.PutUint32(data[:4], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(data[4:6], uint16(len(data)-8))
	binary.LittleEndian.PutUint16(data[10:12], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(data[12:14], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(data[14:16], uint16(2*(len(printName)-1)))
	for index, code := range append(substitute, printName...) {
		binary.LittleEndian.PutUint16(data[16+2*index:], code)
	}
	var returned uint32
	if windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &returned, nil) != nil {
		t.Fatal("declared native fixture could not create a junction")
	}
}

func identityWindowsHandleCount(t *testing.T) uint32 {
	t.Helper()
	procedure := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	if procedure.Find() != nil {
		t.Fatal("fixture handle-count API unavailable")
	}
	var count uint32
	result, _, _ := procedure.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
	if result == 0 {
		t.Fatal("fixture handle-count query failed")
	}
	return count
}
func TestWindowsLocalDiskNameAdmission(t *testing.T) {
	for _, name := range []string{`\Device\HarddiskVolume1`, `\Device\HarddiskVolume1\`, `\Device\HarddiskVolume123\input.txt`} {
		if !localNativeDiskPath(name) {
			t.Fatal("ordinary native disk root or child name refused")
		}
	}
	for _, name := range []string{"", `\Device\HarddiskVolume`, `\Device\HarddiskVolume\`, `\Device\HarddiskVolume1evil`, `\Device\HarddiskVolume1evil\input`, `\Device\Mup\server\share`, `\Device\NamedPipe\input`, `\??\C:\input`, `C:\input`} {
		if localNativeDiskPath(name) {
			t.Fatal("nonlocal or ambiguous native disk name admitted")
		}
	}
}

func TestDisposableWindowsFileIdentityNative(t *testing.T) {
	requireDisposableWindowsIdentityHost(t)
	t.Cleanup(func() { reportDisposableWindowsIdentity(t) })
	directory := t.TempDir()
	path := filepath.Join(directory, "Identity.txt")
	content := []byte("native metadata leaves contents and offsets alone")
	if os.WriteFile(path, content, 0600) != nil {
		t.Fatal("fixture file creation failed")
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal("fixture file open failed")
	}
	defer file.Close()
	opened, err := FromFile(file)
	if err != nil || opened.Kind != Regular || opened.ID.FileID == ([16]byte{}) || opened.Size != int64(len(content)) {
		t.Fatal("borrowed disk handle lacks native identity")
	}

	t.Run("drive-root-native-and-ordinary-handle-parity", func(t *testing.T) {
		root := filepath.VolumeName(directory) + `\`
		file, err := os.Open(root)
		if err != nil {
			t.Fatal("ordinary drive-root metadata handle unavailable")
		}
		defer func() {
			if file.Close() != nil {
				t.Error("ordinary drive-root handle close failed")
			}
		}()
		borrowed, borrowedErr := FromFile(file)
		named, namedErr := FromPath(root, false)
		if borrowedErr != nil || namedErr != nil || borrowed.Kind != Directory || named.Kind != Directory || borrowed.ID != named.ID {
			identityWindowsRootDiagnostic(t, root)
			t.Fatal("drive-root identity differs between ordinary and native metadata handles")
		}
	})

	t.Run("full-native-id-aliases-and-borrowed-lifetime", func(t *testing.T) {
		var identity windowsIDInfo
		connection, err := file.SyscallConn()
		if err != nil {
			t.Fatal("fixture descriptor unavailable")
		}
		var queryErr error
		if connection.Control(func(raw uintptr) {
			queryErr = windows.GetFileInformationByHandleEx(windows.Handle(raw), windows.FileIdInfo,
				(*byte)(unsafe.Pointer(&identity)), uint32(unsafe.Sizeof(identity)))
		}) != nil || queryErr != nil || opened.ID != (ID{identity.Volume, identity.FileID}) {
			t.Fatal("helper narrowed or changed native FileIdInfo")
		}
		alias := filepath.Join(directory, "hard-link.txt")
		if os.Link(path, alias) != nil {
			t.Fatal("fixture hard link creation failed")
		}
		working, err := os.Getwd()
		if err != nil {
			t.Fatal("fixture working directory unavailable")
		}
		relative, err := filepath.Rel(working, path)
		if err != nil {
			t.Fatal("fixture relative path unavailable")
		}
		for _, candidate := range []string{path, alias, relative, strings.ToUpper(path), path + ". "} {
			state, err := FromPath(candidate, true)
			if err != nil || state.Kind != Regular || state.ID != opened.ID {
				t.Fatal("ordinary local alias differs from borrowed native object")
			}
		}
		if _, err := file.Seek(3, io.SeekStart); err != nil {
			t.Fatal("fixture seek failed")
		}
		if _, err := FromFile(file); err != nil {
			t.Fatal("second borrowed identity failed")
		}
		position, err := file.Seek(0, io.SeekCurrent)
		if err != nil || position != 3 {
			t.Fatal("identity query changed borrowed offset or lifetime")
		}
		remaining, err := io.ReadAll(file)
		if err != nil || !bytes.Equal(remaining, content[3:]) {
			t.Fatal("identity query closed or changed borrowed descriptor")
		}
	})

	t.Run("metadata-only-access-and-ads-base-identity", func(t *testing.T) {
		stream := path + ":identity-stream"
		streamData := []byte("separate stream")
		if os.WriteFile(stream, streamData, 0600) != nil {
			t.Fatal("fixture ADS creation failed")
		}
		for _, candidate := range []string{path + "::$DATA", stream, stream + ":$DATA"} {
			state, err := FromPath(candidate, true)
			if err != nil || state.Kind != Regular || state.ID != opened.ID {
				t.Fatal("ADS identity differs from base object")
			}
		}
		streamFile, err := os.Open(stream)
		if err != nil {
			t.Fatal("fixture ADS handle unavailable")
		}
		state, identityErr := FromFile(streamFile)
		closeErr := streamFile.Close()
		if identityErr != nil || closeErr != nil || state.ID != opened.ID || state.Size != int64(len(streamData)) {
			t.Fatal("borrowed ADS identity differs from its native base")
		}
		encoded, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal("fixture metadata path unavailable")
		}
		handle, err := windows.CreateFile(encoded, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatal("fixture metadata-only handle unavailable")
		}
		metadata := os.NewFile(uintptr(handle), "metadata-only-fixture")
		if metadata == nil {
			_ = windows.CloseHandle(handle)
			t.Fatal("fixture metadata descriptor unavailable")
		}
		state, identityErr = FromFile(metadata)
		closeErr = metadata.Close()
		if identityErr != nil || closeErr != nil || state.ID != opened.ID {
			t.Fatal("identity unexpectedly requires file data access")
		}
		stored, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(stored, content) {
			t.Fatal("metadata query changed base contents")
		}
		stored, err = os.ReadFile(stream)
		if err != nil || !bytes.Equal(stored, streamData) {
			t.Fatal("metadata query changed ADS contents")
		}
	})

	t.Run("write-only-and-append-only-borrowed-outputs", func(t *testing.T) {
		appendOnly, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal("fixture append-only output unavailable")
		}
		state, identityErr := FromFile(appendOnly)
		closeErr := appendOnly.Close()
		if identityErr != nil || closeErr != nil || state.Kind != Regular || state.ID != opened.ID {
			t.Fatal("ordinary append-only redirected output lost native identity")
		}
		encoded, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal("fixture write-only path unavailable")
		}
		for _, access := range []uint32{windows.GENERIC_WRITE, windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA | windows.READ_CONTROL | windows.SYNCHRONIZE} {
			handle, err := windows.CreateFile(encoded, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
			if err != nil {
				t.Fatal("fixture write-only native output unavailable")
			}
			output := os.NewFile(uintptr(handle), "write-only-output-fixture")
			if output == nil {
				_ = windows.CloseHandle(handle)
				t.Fatal("fixture output descriptor unavailable")
			}
			state, identityErr := FromFile(output)
			closeErr := output.Close()
			if identityErr != nil || closeErr != nil || state.Kind != Regular || state.ID != opened.ID {
				t.Fatal("native write-only output unexpectedly requires data or attribute read access")
			}
		}
		overlappedHandle, err := windows.CreateFile(encoded, windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED, 0)
		if err != nil {
			t.Fatal("fixture overlapped native output unavailable")
		}
		overlapped := os.NewFile(uintptr(overlappedHandle), "overlapped-output-fixture")
		if overlapped == nil {
			_ = windows.CloseHandle(overlappedHandle)
			t.Fatal("fixture overlapped descriptor unavailable")
		}
		state, identityErr = FromFile(overlapped)
		closeErr = overlapped.Close()
		if identityErr != nil || closeErr != nil || state.Kind != Regular || state.ID != opened.ID {
			t.Fatal("synchronous identity query failed for an overlapped borrowed output")
		}
		stored, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(stored, content) {
			t.Fatal("write-only identity queries changed output contents")
		}
	})
	t.Run("relative-absolute-directory-and-nofollow-links", func(t *testing.T) {
		for _, target := range []string{filepath.Base(path), path} {
			name := "relative-link"
			if filepath.IsAbs(target) {
				name = "absolute-link"
			}
			link := filepath.Join(directory, name)
			identityWindowsLink(t, target, link, false)
			leaf, err := FromPath(link, false)
			if err != nil || leaf.Kind != Reparse || leaf.ID == opened.ID {
				t.Fatal("nofollow leaf did not identify native reparse object")
			}
			followed, err := FromPath(link, true)
			if err != nil || followed.Kind != Regular || followed.ID != opened.ID {
				t.Fatal("followed file link did not identify local target")
			}
		}
		directoryLink := filepath.Join(directory, "directory-link")
		identityWindowsLink(t, directory, directoryLink, true)
		state, err := FromPath(filepath.Join(directoryLink, filepath.Base(path)), false)
		if err != nil || state.Kind != Regular || state.ID != opened.ID {
			t.Fatal("intermediate directory link did not resolve through local metadata")
		}
		junction := filepath.Join(directory, "junction")
		identityWindowsJunction(t, directory, junction)
		if leaf, err := FromPath(junction, false); err != nil || leaf.Kind != Reparse {
			t.Fatal("junction nofollow leaf did not identify mount-point reparse")
		}
		state, err = FromPath(filepath.Join(junction, filepath.Base(path)), true)
		if err != nil || state.Kind != Regular || state.ID != opened.ID {
			t.Fatal("junction target did not resolve to the local native object")
		}
		child := filepath.Join(directory, "child")
		if os.Mkdir(child, 0700) != nil {
			t.Fatal("fixture child creation failed")
		}
		parentLink := filepath.Join(child, "parent-link")
		identityWindowsLink(t, `..\`+filepath.Base(path), parentLink, false)
		state, err = FromPath(parentLink, true)
		if err != nil || state.ID != opened.ID {
			t.Fatal("relative parent target did not resolve safely")
		}
		dangling := filepath.Join(directory, "dangling")
		identityWindowsLink(t, "missing-local-target", dangling, false)
		if state, err := FromPath(dangling, false); err != nil || state.Kind != Reparse {
			t.Fatal("dangling nofollow leaf was not retained")
		}
		if _, err := FromPath(dangling, true); err != os.ErrNotExist {
			t.Fatal("genuinely missing followed target was not reported as absent")
		}
		cycle := filepath.Join(directory, "cycle")
		identityWindowsLink(t, "cycle", cycle, false)
		if state, err := FromPath(cycle, true); err != ErrUnavailable || state != (State{}) {
			t.Fatal("cyclic reparse resolution did not refuse within its bound")
		}
		remote := filepath.Join(directory, "remote-link")
		identityWindowsLink(t, `\\identity-fixture.invalid\no-share\target`, remote, false)
		if state, err := FromPath(remote, false); err != nil || state.Kind != Reparse {
			t.Fatal("remote reparse leaf metadata was unavailable")
		}
		if state, err := FromPath(remote, true); err != ErrUnavailable || state != (State{}) {
			t.Fatal("remote reparse target was admitted")
		}
	})

	t.Run("directories-pipes-and-fixed-errors", func(t *testing.T) {
		state, err := FromPath(directory, false)
		if err != nil || state.Kind != Directory {
			t.Fatal("directory metadata misclassified")
		}
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal("fixture pipe unavailable")
		}
		defer reader.Close()
		defer writer.Close()
		for _, pipe := range []*os.File{reader, writer} {
			state, err := FromFile(pipe)
			if err != nil || state.Kind != Other || state.ID != (ID{}) {
				t.Fatal("pipe unexpectedly treated as regular disk identity")
			}
		}
		for _, candidate := range []string{"", `\\server\share\file`, `\\?\C:\file`, `\\.\NUL`, `\??\C:\file`, `\Device\HarddiskVolume1\file`, `C:\NUL.txt`, `C:\CON .txt`, path + ":stream:$INDEX_ALLOCATION", path + "\x00secret"} {
			state, err := FromPath(candidate, true)
			if err != ErrUnavailable || state != (State{}) {
				t.Fatal("namespace, device or malformed path did not fail closed")
			}
			var native *os.PathError
			if errors.As(err, &native) {
				t.Fatal("native pathname error escaped redaction")
			}
		}
		if state, err := FromPath(filepath.Join(directory, "absent-private-path"), true); err != os.ErrNotExist || state != (State{}) {
			t.Fatal("genuine absence lost its fixed missing sentinel")
		}
		if _, err := FromFile(nil); err != ErrUnavailable {
			t.Fatal("nil borrowed file accepted")
		}
		closed, err := os.Open(path)
		if err != nil || closed.Close() != nil {
			t.Fatal("fixture closed descriptor unavailable")
		}
		if state, err := FromFile(closed); err != ErrUnavailable || state != (State{}) {
			t.Fatal("closed borrowed file accepted")
		}
	})

	t.Run("owned-metadata-probes-close-on-success-and-failure", func(t *testing.T) {
		// Warm up procedure/descriptor caches before comparing native handle
		// counts. Each pass opens ancestors plus a leaf or missing-leaf probe.
		if _, err := FromPath(path, true); err != nil {
			t.Fatal("fixture identity warmup failed")
		}
		before := identityWindowsHandleCount(t)
		for iteration := 0; iteration < 32; iteration++ {
			if _, err := FromPath(path, true); err != nil {
				t.Fatal("repeated metadata probe failed")
			}
			if _, err := FromPath(filepath.Join(directory, "missing-probe"), true); err != os.ErrNotExist {
				t.Fatal("repeated missing metadata probe changed error")
			}
		}
		after := identityWindowsHandleCount(t)
		if after > before+1 {
			t.Fatal("owned metadata probe handles accumulated")
		}
	})
	t.Run("every-thread-impersonation-level-refuses", func(t *testing.T) {
		runtime.LockOSThread()
		restored := true
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		defer func() {
			if !restored {
				if windows.RevertToSelf() != nil {
					t.Error("fixture thread context could not be restored")
					return
				}
				restored = true
			}
		}()
		var primary windows.Token
		if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &primary) != nil {
			t.Fatal("fixture process token unavailable")
		}
		defer primary.Close()
		for _, level := range []uint32{windows.SecurityIdentification, windows.SecurityImpersonation} {
			var impersonation windows.Token
			if windows.DuplicateTokenEx(primary, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, level, windows.TokenImpersonation, &impersonation) != nil {
				t.Fatal("fixture token duplication failed")
			}
			if windows.SetThreadToken(nil, impersonation) != nil {
				_ = impersonation.Close()
				t.Fatal("fixture thread token assignment failed")
			}
			restored = false
			openedState, openedErr := FromFile(file)
			namedState, namedErr := FromPath(path, true)
			if windows.RevertToSelf() != nil {
				_ = impersonation.Close()
				t.Fatal("fixture context restore failed")
			}
			restored = true
			if impersonation.Close() != nil {
				t.Fatal("fixture token close failed")
			}
			if openedErr != ErrUnavailable || namedErr != ErrUnavailable || openedState != (State{}) || namedState != (State{}) {
				t.Fatal("impersonated thread attributed metadata to process context")
			}
		}
		after, err := FromFile(file)
		if err != nil || after.ID != opened.ID {
			t.Fatal("restored process identity did not retain borrowed object")
		}
	})
}

func identityWindowsRootDiagnostic(t *testing.T, root string) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	principal, principalErr := principalSnapshot()
	if principalErr != nil {
		t.Log("root contract: own-process-context=false")
		return
	}
	context := windowsContext{principal}
	drive, err := windows.UTF16PtrFromString(root[:2])
	if err != nil {
		t.Log("root contract: drive-encoding=false")
		return
	}
	var mapping [windowsPathLimit]uint16
	n, err := windows.QueryDosDevice(drive, &mapping[0], uint32(len(mapping)))
	if err != nil || n == 0 || n > uint32(len(mapping)) {
		t.Log("root contract: mapping-query=false")
		return
	}
	target := windows.UTF16ToString(mapping[:n])
	if !localNativeDiskPath(target) || strings.Contains(strings.TrimPrefix(target, `\Device\HarddiskVolume`), `\`) {
		t.Log("root contract: direct-local-mapping=false")
		return
	}
	name, err := windows.NewNTUnicodeString(target + `\`)
	if err != nil {
		t.Log("root contract: native-name-encoding=false")
		return
	}
	attrs := windows.OBJECT_ATTRIBUTES{ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, &attrs, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_NO_RECALL, 0, 0)
	runtime.KeepAlive(name)
	if handle != 0 && handle != windows.InvalidHandle {
		defer func() {
			if context.close(handle) != nil {
				t.Error("diagnostic root close failed")
			}
		}()
	}
	if err != nil {
		t.Logf("root contract: native-open=false access-denied=%t invalid-parameter=%t name-invalid=%t", errors.Is(err, windows.STATUS_ACCESS_DENIED), errors.Is(err, windows.STATUS_INVALID_PARAMETER), errors.Is(err, windows.STATUS_OBJECT_NAME_INVALID))
		return
	}
	t.Logf("root contract: native-open=true opened-status=%t opened-information=%t", status.Status == 0, status.Information == 1)
	var kind uint32
	kind, err = windows.GetFileType(handle)
	t.Logf("root contract: disk-type=%t", err == nil && kind == windows.FILE_TYPE_DISK)
	t.Logf("root contract: local-opened-name=%t", context.localDisk(handle) == nil)
	var metadata windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(handle, &metadata)
	t.Logf("root contract: legacy-metadata=%t directory=%t", err == nil, metadata.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0)
	var id windowsIDInfo
	err = windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id)))
	t.Logf("root contract: full-id-query=%t nonzero-id=%t", err == nil, id.FileID != ([16]byte{}))
}
