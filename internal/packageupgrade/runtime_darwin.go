//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

func normalizeDeploymentImage(path string) string {
	// APFS firmlinks can expose the same boot-data vnode under this fixed
	// mount prefix. No caller/environment selects another authority.
	if strings.HasPrefix(path, "/System/Volumes/Data/Library/Application Support/") {
		return strings.TrimPrefix(path, "/System/Volumes/Data")
	}
	return path
}
func runtimeImageSlot(path string) (string, bool, error) {
	path = normalizeDeploymentImage(path)
	if path == deploymentParent+"/"+deploymentIncoming || strings.HasPrefix(path, deploymentParent+"/"+deploymentIncoming+"/") {
		return "", true, errors.New("launch the installed application to use this version")
	}
	prefix := deploymentParent + "/" + deploymentRoot + "/"
	if !strings.HasPrefix(path, prefix) {
		return "", false, nil
	}
	relative := strings.TrimPrefix(path, prefix)
	parts := strings.Split(relative, "/")
	if len(parts) != 6 || parts[0] != "versions" || !slotName.MatchString(parts[1]) || strings.Join(parts[2:], "/") != "AccessWeaver.app/Contents/MacOS/accessweaver" {
		return "", true, errors.New("unrecognized installed application location")
	}
	return parts[1], true, nil
}
func runtimeFileAt(root *os.File, owner uint32) (*os.File, error) {
	return nativeRuntimeReads().runtimeFileAt(root, owner)
}
func (r runtimeReadOps) runtimeFileAt(root *os.File, owner uint32) (*os.File, error) {
	file, e := darwintrust.OpenRegularAt(root, runtimeLeaseName, owner)
	if e != nil {
		return nil, e
	}
	if e = deploymentObject(file, false, owner, 0644); e == nil {
		var info os.FileInfo
		info, e = file.Stat()
		if e == nil && info.Size() != 0 {
			e = errors.New("runtime coordination file is not empty")
		}
	}
	if e != nil {
		return nil, r.finish(file, e)
	}
	return file, nil
}
func sameRuntimeFile(root, held *os.File, owner uint32) error {
	return nativeRuntimeReads().sameRuntimeFile(root, held, owner)
}
func (r runtimeReadOps) sameRuntimeFile(root, held *os.File, owner uint32) (failure error) {
	current, e := r.runtimeFileAt(root, owner)
	if e != nil {
		return e
	}
	defer func() { failure = r.finish(current, failure) }()
	a, e := held.Stat()
	if e != nil {
		return e
	}
	b, e := current.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(a, b) {
		return errors.New("runtime coordination identity changed")
	}
	return nil
}
func parseRuntimeDescriptor(value string) (int, error) {
	if value == "" || len(value) > 4 {
		return 0, errors.New("invalid inherited runtime descriptor")
	}
	fd, e := strconv.Atoi(value)
	if e != nil || fd < 3 || fd > 1024 || strconv.Itoa(fd) != value {
		return 0, errors.New("invalid inherited runtime descriptor")
	}
	return fd, nil
}
func inheritedRuntimeFile(fd int, expected *os.File) (*os.File, error) {
	return nativeRuntimeReads().inheritedRuntimeFile(fd, expected)
}
func (r runtimeReadOps) inheritedRuntimeFile(fd int, expected *os.File) (*os.File, error) {
	if fd == int(expected.Fd()) {
		return nil, errors.New("inherited descriptor was not present before lease lookup")
	}
	// Do not wrap/close an untrusted descriptor before identity/access checks:
	// it may belong to an unrelated runtime/network/file resource.
	var st syscall.Stat_t
	if e := syscall.Fstat(fd, &st); e != nil {
		return nil, e
	}
	info, e := expected.Stat()
	if e != nil {
		return nil, e
	}
	want := info.Sys().(*syscall.Stat_t)
	if st.Dev != want.Dev || st.Ino != want.Ino || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != 0 || st.Gid != 0 || st.Size != 0 || st.Mode&07777 != 0644 {
		return nil, errors.New("inherited runtime descriptor identity differs")
	}
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if e != nil {
		return nil, e
	}
	if flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, errors.New("inherited runtime descriptor must be read-only")
	}
	// Reapplying a shared flock to the inherited open-file description keeps
	// an existing shared lease continuous, and also validates a forged hint
	// that references the real file without actually holding a lease.
	if e = unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB); e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), expected.Name())
	if e = deploymentObject(f, false, 0, 0644); e != nil {
		return nil, r.finish(f, e)
	}
	flags, e = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if e == nil {
		_, e = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC)
	}
	if e != nil {
		return nil, r.finish(f, e)
	}
	return f, nil
}
func acquireRuntimeReader(root *os.File) (*RuntimeLease, error) {
	return nativeRuntimeReads().acquireRuntimeReader(root)
}
func (r runtimeReadOps) acquireRuntimeReader(root *os.File) (*RuntimeLease, error) {
	expected, err := r.runtimeFileAt(root, 0)
	if err != nil {
		return nil, err
	}
	hint, hasHint := os.LookupEnv(runtimeLeaseEnvironment)
	if hasHint {
		fd, parsed := parseRuntimeDescriptor(hint)
		if parsed != nil {
			return nil, r.finish(expected, parsed)
		}
		inherited, adopted := r.inheritedRuntimeFile(fd, expected)
		completed := r.finish(expected, adopted)
		if completed != nil {
			return nil, r.finish(inherited, completed)
		}
		expected = inherited
		if err = os.Unsetenv(runtimeLeaseEnvironment); err != nil {
			return nil, r.finish(expected, err)
		}
	} else if err = unix.Flock(int(expected.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		return nil, r.finish(expected, fmt.Errorf("installation is changing; retry after it finishes: %w", err))
	}
	if err = r.sameRuntimeFile(root, expected, 0); err != nil {
		return nil, r.finish(expected, err)
	}
	return &RuntimeLease{file: expected}, nil
}

// AcquireInstalledRuntime uses the kernel's own process-image path. Installed
// cores must be the active immutable copy; receipt-owned input is never a
// controller. Portable/legacy locations retain their existing behavior.
func AcquireInstalledRuntime() (lease *RuntimeLease, err error) {
	image, e := currentKernelExecutable()
	if e != nil {
		return nil, fmt.Errorf("inspect running application image: %w", e)
	}
	slot, managed, e := runtimeImageSlot(image)
	if e != nil {
		return nil, e
	}
	if !managed {
		loader, loadErr := os.Executable()
		if loadErr != nil {
			return nil, loadErr
		}
		_, loaderManaged, _ := runtimeImageSlot(filepath.Clean(loader))
		if loaderManaged {
			return nil, errors.New("running image does not match the installed application location")
		}
		if _, present := os.LookupEnv(runtimeLeaseEnvironment); present {
			return nil, errors.New("runtime descriptor supplied to an unmanaged application")
		}
		return nil, nil
	}
	parent, e := darwintrust.OpenRootDirectory(deploymentParent)
	if e != nil {
		return nil, e
	}
	r := nativeRuntimeReads()
	return acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error {
		active, build, err := r.readActiveRuntime(root, slot)
		if err != nil {
			return err
		}
		if err = verifyRuntimeImage(image, installedCorePath(active.ID), build, buildinfo.Current()); err != nil {
			return err
		}
		if err = r.sameDeploymentEntry(parent, deploymentRoot, root, 0); err != nil {
			return err
		}
		return r.sameRuntimeFile(root, lease.file, 0)
	})
}

// All callers hold the shared runtime lease. There is no path/version/record
// supplied by a caller; only the fixed protected authority selects a core.
func readActiveRuntime(root *os.File, expectedSlot string) (deploymentSlot, buildinfo.Info, error) {
	return nativeRuntimeReads().readActiveRuntime(root, expectedSlot)
}
func (r runtimeReadOps) readActiveRuntime(root *os.File, expectedSlot string) (active deploymentSlot, identity buildinfo.Info, failure error) {
	stateDir, e := r.deploymentDirectory(root, "state", 0, false)
	if e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	reader := &deploymentStore{owner: 0}
	encoded, readErr := r.readRecord(reader, stateDir)
	e = r.finish(stateDir, readErr)
	if e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	state, e := decodeDeployment(encoded)
	if e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	if expectedSlot != "" && state.Active.ID != expectedSlot {
		return deploymentSlot{}, buildinfo.Info{}, errors.New("this installed version is no longer active; launch the current application")
	}
	if state.Active.ID == "" {
		return deploymentSlot{}, buildinfo.Info{}, errors.New("AccessWeaver is not active; install or repair the application")
	}
	versions, e := r.deploymentDirectory(root, "versions", 0, false)
	if e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	defer func() {
		failure = r.finish(versions, failure)
		if failure != nil {
			active = deploymentSlot{}
			identity = buildinfo.Info{}
		}
	}()
	reader.versions = versions
	if e = r.verifySlot(reader, state.Active); e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	dir, e := r.openSlot(reader, state.Active)
	if e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	defer func() {
		failure = r.finish(dir, failure)
		if failure != nil {
			active = deploymentSlot{}
			identity = buildinfo.Info{}
		}
	}()
	app, e := r.directoryAt(dir, "AccessWeaver.app")
	if e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	defer func() {
		failure = r.finish(app, failure)
		if failure != nil {
			active = deploymentSlot{}
			identity = buildinfo.Info{}
		}
	}()
	buildData, e := r.readPath(app, "Contents/Resources/BUILD-INFO.json", 16384)
	if e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	build, e := decodeBuild(buildData, runtime.GOARCH)
	if e != nil {
		return deploymentSlot{}, buildinfo.Info{}, e
	}
	return state.Active, build, nil
}
func installedCorePath(slot string) string {
	return deploymentParent + "/" + deploymentRoot + "/versions/" + slot + "/AccessWeaver.app/Contents/MacOS/accessweaver"
}

func verifyRuntimeImage(image, core string, build, expectedBuild buildinfo.Info) error {
	actual, err := os.Stat(image)
	if err != nil {
		return err
	}
	expected, err := os.Stat(core)
	if err != nil {
		return err
	}
	if !os.SameFile(actual, expected) {
		return errors.New("running application image identity differs")
	}
	if build != expectedBuild {
		return errors.New("running application build differs from active installation")
	}
	return nil
}
