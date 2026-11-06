//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// LaunchInstalled replaces this ordinary-user process with the fully verified
// active core. No caller path, receipt, environment or launcher location picks
// its authority. The shared lease survives exec through one inherited OFD.
func LaunchInstalled(args []string) (err error) {
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return errors.New("launch AccessWeaver as your ordinary desktop user")
	}
	args, e := installedLaunchArguments(args)
	if e != nil {
		return e
	}
	if _, present := os.LookupEnv(runtimeLeaseEnvironment); present {
		return errors.New("runtime descriptor supplied to application launcher")
	}
	parent, e := darwintrust.OpenRootDirectory(deploymentParent)
	if e != nil {
		return e
	}
	r := nativeRuntimeReads()
	var core string
	lease, err := acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error {
		active, _, err := r.readActiveRuntime(root, "")
		if err != nil {
			return err
		}
		if err = r.sameDeploymentEntry(parent, deploymentRoot, root, 0); err != nil {
			return err
		}
		if err = r.sameRuntimeFile(root, lease.file, 0); err != nil {
			return err
		}
		core = installedCorePath(active.ID)
		return nil
	})
	if err != nil {
		return err
	}
	defer func() { err = r.finishLease(lease, err) }()
	return execWithRuntimeLease(lease, core, args, os.Environ())
}

// Duplicate the existing open-file description, never unlock/relock between
// images. Every metadata descriptor and the original lease remain CLOEXEC.
// Failure closes only our duplicate; the caller still owns its original lease.
func execWithRuntimeLease(lease *RuntimeLease, path string, args, environment []string) (err error) {
	if lease == nil || lease.file == nil {
		return errors.New("runtime lease is absent")
	}
	fd, e := unix.FcntlInt(lease.file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	if fd > 1024 {
		return errors.New("runtime descriptor exceeds handoff limit")
	}
	env := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, runtimeLeaseEnvironment+"=") {
			env = append(env, entry)
		}
	}
	env = append(env, runtimeLeaseEnvironment+"="+strconv.Itoa(fd))
	argv := append([]string{path}, args...)
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if e != nil {
		return e
	}
	if _, e = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags & ^unix.FD_CLOEXEC); e != nil {
		return e
	}
	if e = unix.Exec(path, argv, env); e != nil {
		return fmt.Errorf("launch active application: %w", e)
	}
	return errors.New("application exec unexpectedly returned")
}
