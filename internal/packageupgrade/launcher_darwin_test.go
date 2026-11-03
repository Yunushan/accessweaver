//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDarwinLauncherExecFailureDoesNotLeakLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease")
	if e := os.WriteFile(path, nil, 0644); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	lease := &RuntimeLease{file: f}
	defer lease.Close()
	if e = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	originalFD := int(f.Fd())
	if e = execWithRuntimeLease(lease, filepath.Join(t.TempDir(), "absent"), nil, []string{runtimeLeaseEnvironment + "=999"}); !errors.Is(e, unix.ENOENT) {
		t.Fatal("missing executable did not return ENOENT", e)
	}
	flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if e != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("original descriptor flags changed", e)
	}
	writer, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	if e = unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); e == nil {
		t.Fatal("failure dropped caller lease")
	}
	if e = lease.Close(); e != nil {
		t.Fatal(e)
	}
	if e = unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatalf("failed exec retained lease: %v; original=%d writer=%d afterClose=%v", e, originalFD, writer.Fd(), leaseFixtureDescriptors(t, path))
	}
}

// Keep this inventory check separate: scanning descriptors between close and
// the writer assertion would change the timing of the immediate-release probe.
func TestDarwinLauncherFailedExecClosesDuplicateDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease")
	if e := os.WriteFile(path, nil, 0644); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	lease := &RuntimeLease{file: f}
	defer lease.Close()
	if e = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	if e = execWithRuntimeLease(lease, filepath.Join(t.TempDir(), "absent"), nil, nil); !errors.Is(e, unix.ENOENT) {
		t.Fatal(e)
	}
	actual := leaseFixtureDescriptors(t, path)
	if len(actual) != 1 || actual[0] != int(f.Fd()) {
		t.Fatalf("failed exec retained duplicate: %v", actual)
	}
}

// Inspect owned fixture descriptors without creating os.File wrappers/finalizers.
// Keep a hard assertion on immediate release; a later retry must not hide a leak.
func leaseFixtureDescriptors(t *testing.T, path string) []int {
	t.Helper()
	info, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	want := info.Sys().(*syscall.Stat_t)
	var descriptors []int
	for fd := 0; fd <= 1024; fd++ {
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) == nil && st.Dev == want.Dev && st.Ino == want.Ino {
			descriptors = append(descriptors, fd)
		}
	}
	return descriptors
}
func TestDarwinLauncherLeaseSurvivesRealExec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease")
	if e := os.WriteFile(path, nil, 0644); e != nil {
		t.Fatal(e)
	}
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestDarwinLauncherLeaseExecHelper$")
	cmd.Env = append(os.Environ(), "ACCESSWEAVER_TEST_LEASE_PHASE=parent", "ACCESSWEAVER_TEST_LEASE_PATH="+path)
	out, e := cmd.CombinedOutput()
	if e != nil || !strings.Contains(string(out), "LEASE-HANDOFF-PASSED") {
		t.Fatalf("real lease handoff failed: %v %s", e, out)
	}
	writer, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	if e = unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal("terminated helper retained lease", e)
	}
}
func TestDarwinLauncherLeaseExecHelper(t *testing.T) {
	phase := os.Getenv("ACCESSWEAVER_TEST_LEASE_PHASE")
	if phase == "" {
		t.Skip("owned subprocess helper")
	}
	path := os.Getenv("ACCESSWEAVER_TEST_LEASE_PATH")
	if phase == "parent" {
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		if e = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); e != nil {
			t.Fatal(e)
		}
		self, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		env := []string{"PATH=/usr/bin:/bin", "ACCESSWEAVER_TEST_LEASE_PHASE=inherited", "ACCESSWEAVER_TEST_LEASE_PATH=" + path}
		t.Fatal(execWithRuntimeLease(&RuntimeLease{file: f}, self, []string{"-test.run=^TestDarwinLauncherLeaseExecHelper$"}, env))
	}
	if phase != "inherited" {
		t.Fatal("unknown test phase")
	}
	fd, e := parseRuntimeDescriptor(os.Getenv(runtimeLeaseEnvironment))
	if e != nil {
		t.Fatal(e)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	got, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	want, e := os.Stat(path)
	if e != nil || !os.SameFile(got, want) {
		t.Fatal("inherited file differs", e)
	}
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("inherited descriptor access", e)
	}
	writer, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	if e = unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); e == nil {
		t.Fatal("exec lost shared lease")
	}
	fmt.Println("LEASE-HANDOFF-PASSED")
}
