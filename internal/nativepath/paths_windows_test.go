//go:build windows

package nativepath

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestNativeLocationsIgnoreUserEnvironment(t *testing.T) {
	system, err := SystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	data, err := ProgramData()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SystemRoot", `C:\untrusted`)
	t.Setenv("ProgramData", `C:\untrusted`)
	t.Setenv("PSModulePath", `C:\untrusted`)
	t.Setenv("COR_PROFILER_PATH", `C:\untrusted.dll`)
	t.Setenv("ProgramFiles", `C:\untrusted`)
	t.Setenv("ProgramFiles(x86)", `C:\untrusted`)
	t.Setenv("CommonProgramFiles", `C:\untrusted`)
	t.Setenv("CORECLR_PROFILER_PATH", `C:\untrusted.dll`)
	actual, err := SystemDirectory()
	if err != nil || actual != system {
		t.Fatal("system directory followed environment", err)
	}
	actual, err = ProgramData()
	if err != nil || actual != data {
		t.Fatal("ProgramData followed environment", err)
	}
	env, err := ProcessEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range env {
		if strings.Contains(item, `C:\untrusted`) {
			t.Fatal("injection reached native environment", item)
		}
	}
	if !filepath.IsAbs(system) || !filepath.IsAbs(data) {
		t.Fatal("native paths not absolute")
	}
}

func TestNativeLocationsBeforeFirstLookupWithPoisonedEnvironment(t *testing.T) {
	system, err := SystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	data, err := ProgramData()
	if err != nil {
		t.Fatal(err)
	}
	blocked := map[string]bool{"SYSTEMROOT": true, "PROGRAMDATA": true, "ALLUSERSPROFILE": true, "SYSTEMDRIVE": true, "ACCESSWEAVER_TEST_NATIVE_SYSTEM": true, "ACCESSWEAVER_TEST_NATIVE_DATA": true}
	var environment []string
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if !blocked[strings.ToUpper(name)] {
			environment = append(environment, item)
		}
	}
	environment = append(environment, `SystemRoot=C:\untrusted`, `ProgramData=C:\untrusted`, `ALLUSERSPROFILE=C:\untrusted`, `SystemDrive=Z:`, "ACCESSWEAVER_TEST_NATIVE_SYSTEM="+system, "ACCESSWEAVER_TEST_NATIVE_DATA="+data)
	command := exec.Command(os.Args[0], "-test.run=^TestNativeLocationChild$")
	command.Env = environment
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native path lookup trusted initial environment: %v %s", err, out)
	}
}
func TestNativeLocationChild(t *testing.T) {
	expectedSystem := os.Getenv("ACCESSWEAVER_TEST_NATIVE_SYSTEM")
	if expectedSystem == "" {
		return
	}
	system, err := SystemDirectory()
	if err != nil || system != expectedSystem {
		t.Fatal("system directory mismatch", system, err)
	}
	data, err := ProgramData()
	if err != nil || data != os.Getenv("ACCESSWEAVER_TEST_NATIVE_DATA") {
		t.Fatal("ProgramData mismatch", data, err)
	}
}

func TestProtectedProfileSettingMatchesNativeDirectoryAPI(t *testing.T) {
	procedure := syscall.NewLazyDLL("userenv.dll").NewProc("GetAllUsersProfileDirectoryW")
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	ok, _, err := procedure.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		t.Fatal(err)
	}
	expected := syscall.UTF16ToString(buffer)
	actual, err := ProgramData()
	if err != nil || !strings.EqualFold(actual, expected) {
		t.Fatal("protected profile setting differs from ordinary native API", actual, expected, err)
	}
}
