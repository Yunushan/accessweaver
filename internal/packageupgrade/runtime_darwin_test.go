//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinRuntimeWriterRefusesSharedLeaseWithoutStateMutation(t *testing.T) {
	parent := t.TempDir()
	s := deploymentFixtureStore(t, parent, nil)
	before := append([]byte{}, s.encoded...)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	file, e := os.Open(filepath.Join(parent, deploymentRoot, runtimeLeaseName))
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	if e = unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(parent)
	if e != nil {
		t.Fatal(e)
	}
	if writer, e := beginDeployment(f, uint32(os.Geteuid()), nil); e == nil {
		writer.Close()
		t.Fatal("writer ignored active runtime lease")
	}
	actual, e := os.ReadFile(filepath.Join(parent, deploymentRoot, "state", deploymentRecord))
	if e != nil || string(actual) != string(before) {
		t.Fatal("busy writer mutated state", e)
	}
	if e = unix.Flock(int(file.Fd()), unix.LOCK_UN); e != nil {
		t.Fatal(e)
	}
	reopened := deploymentFixtureStore(t, parent, nil)
	if string(reopened.encoded) != string(before) {
		t.Fatal("retry lost prior state")
	}
}
func TestDarwinRuntimeMissingCoordinationRequiresExplicitMaintenance(t *testing.T) {
	parent := t.TempDir()
	s := deploymentFixtureStore(t, parent, nil)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(parent, deploymentRoot, runtimeLeaseName)
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(parent)
	if e != nil {
		t.Fatal(e)
	}
	if writer, e := beginDeployment(f, uint32(os.Geteuid()), nil); e == nil {
		writer.Close()
		t.Fatal("missing runtime coordination silently recreated")
	}
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("unsupported authority changed", e)
	}
}
func TestDarwinRuntimeImageAndDescriptorClassification(t *testing.T) {
	id := strings.Repeat("a", 32)
	core := deploymentParent + "/" + deploymentRoot + "/versions/" + id + "/AccessWeaver.app/Contents/MacOS/accessweaver"
	for _, path := range []string{core, "/System/Volumes/Data" + core} {
		slot, managed, e := runtimeImageSlot(path)
		if e != nil || !managed || slot != id {
			t.Fatal(path, slot, managed, e)
		}
	}
	for _, path := range []string{deploymentParent + "/" + deploymentRoot + "/unknown", deploymentParent + "/" + deploymentIncoming + "/input.app"} {
		if _, _, e := runtimeImageSlot(path); e == nil {
			t.Fatal("unexpected managed image accepted", path)
		}
	}
	if _, managed, e := runtimeImageSlot("/Users/example/portable/accessweaver"); e != nil || managed {
		t.Fatal("portable image classification", e)
	}
	for _, text := range []string{"", "0", "2", "03", "-1", "1025", "3 ", "3/other"} {
		if _, e := parseRuntimeDescriptor(text); e == nil {
			t.Fatal("invalid descriptor hint", text)
		}
	}
	if fd, e := parseRuntimeDescriptor("3"); e != nil || fd != 3 {
		t.Fatal(e)
	}
}
func TestDarwinRuntimeForeignDescriptorIsNeverClosed(t *testing.T) {
	dir := t.TempDir()
	expected, e := os.Create(filepath.Join(dir, "expected"))
	if e != nil {
		t.Fatal(e)
	}
	defer expected.Close()
	foreign, e := os.Create(filepath.Join(dir, "foreign"))
	if e != nil {
		t.Fatal(e)
	}
	defer foreign.Close()
	if inherited, e := inheritedRuntimeFile(int(foreign.Fd()), expected); e == nil {
		inherited.Close()
		t.Fatal("foreign descriptor adopted")
	}
	if _, e := foreign.Stat(); e != nil {
		t.Fatal("foreign descriptor was closed", e)
	}
	if inherited, e := inheritedRuntimeFile(int(expected.Fd()), expected); e == nil {
		inherited.Close()
		t.Fatal("newly opened lookup descriptor adopted as inherited")
	}
	if _, e := expected.Stat(); e != nil {
		t.Fatal("lookup descriptor was closed", e)
	}
}
func TestDarwinKernelImageIsNotCallerArgv(t *testing.T) {
	path, e := currentKernelExecutable()
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	loader, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	actual, e := os.Stat(loader)
	if e != nil {
		t.Fatal(e)
	}
	if !os.SameFile(info, actual) {
		t.Fatal("kernel and running test executable differ")
	}
}
