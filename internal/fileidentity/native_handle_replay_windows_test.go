//go:build windows

package fileidentity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process handle attribution for the hosted identity test. PSS captures only this test process's handle
// metadata (flags 0x34), never object names, memory, thread contexts or traces.
// Handle values stay in memory. Only seven public PSS_OBJECT_TYPE counts leave
// this helper: unknown, process, thread, mutant, event, section, semaphore.
// A replay is diagnostic; it cannot erase the original handle-count failure.
type windowsIdentityHandleReplay struct {
	SnapshotComplete bool      `json:"snapshotComplete"`
	HandlesBefore    uint32    `json:"handlesBefore"`
	HandlesAfter     uint32    `json:"handlesAfter"`
	KindsBefore      [7]uint32 `json:"kindsBefore"`
	KindsAfter       [7]uint32 `json:"kindsAfter"`
	NewHandleKinds   [7]uint32 `json:"newHandleKinds"`
}

type windowsIdentityPSSHandleEntry struct {
	Handle                                                                                    uintptr
	Flags, ObjectType                                                                         uint32
	CaptureTime                                                                               windows.Filetime
	Attributes, GrantedAccess, HandleCount, PointerCount, PagedPoolCharge, NonPagedPoolCharge uint32
	CreationTime                                                                              windows.Filetime
	TypeNameLength                                                                            uint16
	TypeName                                                                                  *uint16
	ObjectNameLength                                                                          uint16
	ObjectName                                                                                uintptr
	TypeSpecific                                                                              [6]uintptr
}

// The Windows SDK PSS_HANDLE_ENTRY is 136 bytes on native AMD64 and ARM64.
// Never dereference its optional name or type-specific pointer fields.
// The first seven bins retain the PSS_OBJECT_TYPE order used by the replay.
// File and Token have kernel type names but no dedicated PSS enum value.

func identityWindowsHandleKinds(detailed bool) (values map[uintptr]uint32, complete bool) {
	var entry windowsIdentityPSSHandleEntry
	if unsafe.Sizeof(entry) != 136 || unsafe.Offsetof(entry.TypeName) != 64 ||
		unsafe.Offsetof(entry.ObjectName) != 80 || unsafe.Offsetof(entry.TypeSpecific) != 88 {
		return nil, false
	}
	dll := windows.NewLazySystemDLL("kernel32.dll")
	capture, free, create, release, walk := dll.NewProc("PssCaptureSnapshot"), dll.NewProc("PssFreeSnapshot"),
		dll.NewProc("PssWalkMarkerCreate"), dll.NewProc("PssWalkMarkerFree"), dll.NewProc("PssWalkSnapshot")
	for _, procedure := range []*windows.LazyProc{capture, free, create, release, walk} {
		if procedure.Find() != nil {
			return nil, false
		}
	}
	var snapshot, marker uintptr
	flags := uintptr(0x34) // HANDLES | HANDLE_BASIC_INFORMATION | HANDLE_TYPE_SPECIFIC_INFORMATION.
	if detailed {
		flags = 0x14 // HANDLES | HANDLE_BASIC_INFORMATION, as in the external census.
	}
	status, _, _ := capture.Call(uintptr(windows.CurrentProcess()), flags, 0, uintptr(unsafe.Pointer(&snapshot)))
	if status != 0 || snapshot == 0 {
		return nil, false
	}
	defer func() {
		status, _, _ := free.Call(uintptr(windows.CurrentProcess()), snapshot)
		if status != 0 {
			values, complete = nil, false
		}
	}()
	status, _, _ = create.Call(0, uintptr(unsafe.Pointer(&marker)))
	if status != 0 || marker == 0 {
		return nil, false
	}
	defer func() {
		status, _, _ := release.Call(marker)
		if status != 0 {
			values, complete = nil, false
		}
	}()
	values = make(map[uintptr]uint32)
	for index := 0; index <= 1024; index++ {
		entry = windowsIdentityPSSHandleEntry{}
		status, _, _ = walk.Call(snapshot, 2, marker, uintptr(unsafe.Pointer(&entry)), unsafe.Sizeof(entry))
		if status == 259 {
			return values, true
		} // ERROR_NO_MORE_ITEMS
		if status != 0 || index == 1024 || entry.Handle == 0 || entry.Flags&2 != 0 || entry.ObjectNameLength != 0 {
			return nil, false
		}
		if _, duplicate := values[entry.Handle]; duplicate {
			return nil, false
		}
		kind := entry.ObjectType
		if entry.Flags&1 == 0 {
			kind = 0
		}
		if kind >= 7 {
			return nil, false
		}
		if detailed && entry.TypeNameLength != 0 && entry.TypeName != nil {
			if entry.TypeNameLength > 128 || entry.TypeNameLength%2 != 0 {
				return nil, false
			}
			// TypeName is a kernel type label valid until the next walk. Only
			// fixed categories leave this function, never the label or pointer.
			switch windows.UTF16ToString(unsafe.Slice(entry.TypeName, int(entry.TypeNameLength/2))) {
			case "File":
				kind = windowsIdentityFileHandle
			case "Token":
				kind = windowsIdentityTokenHandle
			case "Process":
				kind = 1
			case "Thread":
				kind = 2
			case "Mutant":
				kind = 3
			case "Event":
				kind = windowsIdentityEventHandle
			case "Section":
				kind = 5
			case "Semaphore":
				kind = 6
			}
		}
		values[entry.Handle] = kind
	}
	return nil, false
}

func identityWindowsMeasuredHandleTypes(before, after map[uintptr]uint32, beforeCount, afterCount uint32) *windowsIdentityHandleWindow {
	result := &windowsIdentityHandleWindow{}
	if before == nil || after == nil {
		return result
	}
	result.SnapshotComplete = true
	result.CountsMatch = uint32(len(before)) == beforeCount && uint32(len(after)) == afterCount
	for _, kind := range before {
		result.KindsBefore[kind]++
	}
	for handle, kind := range after {
		result.KindsAfter[kind]++
		if previous, known := before[handle]; !known || previous != kind {
			result.NewHandleKinds[kind]++
		}
	}
	return result
}

func identityWindowsReplayHandleGrowth(t *testing.T, path, missing string) *windowsIdentityHandleReplay {
	t.Helper()
	result := &windowsIdentityHandleReplay{}
	// Warm and release diagnostic-owned API state before the separate replay.
	if _, ok := identityWindowsHandleKinds(false); !ok {
		return result
	}
	before, ok := identityWindowsHandleKinds(false)
	if !ok {
		return result
	}
	result.HandlesBefore = identityWindowsHandleCount(t)
	for iteration := 0; iteration < 32; iteration++ {
		if _, err := FromPath(path, true); err != nil {
			t.Error("diagnostic metadata replay failed")
			return result
		}
		if _, err := FromPath(missing, true); err != os.ErrNotExist {
			t.Error("diagnostic missing metadata replay failed")
			return result
		}
	}
	result.HandlesAfter = identityWindowsHandleCount(t)
	after, ok := identityWindowsHandleKinds(false)
	if !ok {
		return result
	}
	for _, kind := range before {
		result.KindsBefore[kind]++
	}
	for handle, kind := range after {
		result.KindsAfter[kind]++
		if previous, known := before[handle]; !known || previous != kind {
			result.NewHandleKinds[kind]++
		}
	}
	clear(before)
	clear(after)
	result.SnapshotComplete = true
	return result
}

// Exercise the native SDK layout and capture/free/walk contract on the opted-in
// hosted VM even when the original resource probe does not fail. This does not
// convert the separate replay's counts into a resource-leak acceptance result.
func TestDisposableWindowsHandleReplayNative(t *testing.T) {
	requireDisposableWindowsIdentityHost(t)
	result := &windowsIdentityHandleReplay{}
	t.Cleanup(func() {
		commit, run := os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_RUN_ID")
		workspace := os.Getenv("GITHUB_WORKSPACE")
		absolute, err := filepath.Abs(workspace)
		if err != nil || workspace == "" || !filepath.IsAbs(workspace) || absolute != workspace ||
			(len(commit) != 40 && len(commit) != 64) || strings.Trim(commit, "0123456789abcdef") != "" ||
			run == "" || strings.Trim(run, "0123456789") != "" {
			t.Error("native diagnostic receipt identity unavailable")
			return
		}
		report := struct {
			SchemaVersion                   int                          `json:"schemaVersion"`
			SourceCommit                    string                       `json:"sourceCommit"`
			RunID                           string                       `json:"runID"`
			Arch                            string                       `json:"arch"`
			Scope                           string                       `json:"scope"`
			Replay                          *windowsIdentityHandleReplay `json:"replay"`
			Passed                          bool                         `json:"passed"`
			ProductionQualificationComplete bool                         `json:"productionQualificationComplete"`
		}{1, commit, run, runtime.GOARCH, "self-handle-type-diagnostic-contract", result, !t.Failed(), false}
		data, err := json.MarshalIndent(report, "", "  ")
		folder := filepath.Join(workspace, "build", "windows-audit-identity-input-checks")
		if err != nil || len(data) > 2048 || os.MkdirAll(folder, 0755) != nil {
			t.Error("native diagnostic receipt encoding unavailable")
			return
		}
		file, err := os.OpenFile(filepath.Join(folder, "handle-replay-"+runtime.GOARCH+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			t.Error("native diagnostic receipt unavailable")
			return
		}
		data = append(data, '\n')
		n, writeErr := file.Write(data)
		syncErr, closeErr := file.Sync(), file.Close()
		if n != len(data) || writeErr != nil || syncErr != nil || closeErr != nil {
			t.Error("native diagnostic receipt incomplete")
		}
	})
	directory := t.TempDir()
	path := filepath.Join(directory, "metadata.txt")
	if os.WriteFile(path, []byte("inert native metadata diagnostic"), 0600) != nil {
		t.Fatal("native diagnostic fixture unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("native census fixture file unavailable")
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		_ = file.Close()
		t.Fatal("native census fixture token unavailable")
	}
	fileHandle, tokenHandle := file.Fd(), uintptr(token)
	kinds, complete := identityWindowsHandleKinds(true)
	closeFile, closeToken := file.Close(), token.Close()
	if closeFile != nil || closeToken != nil || !complete ||
		kinds[fileHandle] != windowsIdentityFileHandle || kinds[tokenHandle] != windowsIdentityTokenHandle {
		t.Fatal("native census did not verify the owned file and token types")
	}
	result = identityWindowsReplayHandleGrowth(t, path, filepath.Join(directory, "missing"))
	if !result.SnapshotComplete {
		t.Fatal("native handle snapshot contract unavailable")
	}
	for index, count := range result.NewHandleKinds {
		if count > result.KindsAfter[index] {
			t.Fatal("native handle type counts inconsistent")
		}
	}
}
