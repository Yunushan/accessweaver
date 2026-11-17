package engine

import (
	"errors"
	"os"
	"sync"
	"syscall"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// proc_listpgrppids takes a process-group ID and a pid_t buffer size in bytes.
// Keep the fixed OS library available for the process after resolving its
// public entry point. A loader or inventory failure preserves the signal error.
type darwinGroupMembers func(int32, *[2]int32, int32) int32

var darwinListGroup = sync.OnceValue(func() darwinGroupMembers {
	library, err := purego.Dlopen("/usr/lib/libproc.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil
	}
	address, err := purego.Dlsym(library, "proc_listpgrppids")
	if err != nil || address == 0 {
		_ = purego.Dlclose(library)
		return nil
	}
	var list darwinGroupMembers
	purego.RegisterFunc(&list, address)
	return list
})

func groupSignalAlreadyExited(pgid int, signalErr error) bool {
	if !errors.Is(signalErr, syscall.EPERM) {
		return false
	}
	return onlyObservedDarwinGroupLeader(pgid, darwinListGroup())
}

// Explicit retry can acquire the owner's mutex before the exit observer
// publishes its result. A waitable direct child is an independent exit proof.
// The owner still holds this generation unreaped throughout the native queries.
func retryGroupAlreadyExited(pgid int, signalErr error) bool {
	if !errors.Is(signalErr, syscall.EPERM) || pgid <= 1 || int(int32(pgid)) != pgid {
		return false
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pgid)
	return err == nil && darwinWaitableGroupLeader(info, int32(pgid), int32(os.Getpid())) &&
		groupSignalAlreadyExited(pgid, signalErr)
}

func darwinWaitableGroupLeader(info *unix.KinfoProc, pgid, parent int32) bool {
	const zombie = 5 // SZOMB in Darwin's <sys/proc.h>.
	return info != nil && info.Proc.P_stat == zombie &&
		info.Proc.P_pid == pgid && info.Eproc.Pgid == pgid && info.Eproc.Ppid == parent
}

func onlyObservedDarwinGroupLeader(pgid int, list darwinGroupMembers) bool {
	if list == nil || pgid <= 1 || int(int32(pgid)) != pgid {
		return false
	}
	// POSIX group kill on Darwin can return EPERM when the only member is
	// the exited, unreaped leader. libproc snapshots membership under the
	// process-list lock. With two slots, truncation cannot yield one member.
	// Require the exact leader that the caller has already observed exiting.
	// An empty, denied, ambiguous or multi-member result preserves EPERM.
	var members [2]int32
	leader := int32(pgid)
	return list(leader, &members, 8) == 1 && members == [2]int32{leader, 0}
}
