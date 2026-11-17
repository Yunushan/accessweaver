package engine

import (
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDarwinExitedGroupRequiresExactUnreapedLeader(t *testing.T) {
	const leader = 12345
	cases := []struct {
		name    string
		count   int32
		members [2]int32
		want    bool
	}{
		{"only-leader", 1, [2]int32{leader, 0}, true},
		{"empty-or-denied", 0, [2]int32{}, false},
		{"other-member", 1, [2]int32{leader - 1, 0}, false},
		{"live-or-unknown-descendant", 2, [2]int32{leader, leader + 1}, false},
		{"invalid-size", -1, [2]int32{leader, 0}, false},
		{"inconsistent-slot", 1, [2]int32{leader, leader + 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := onlyObservedDarwinGroupLeader(leader, func(pgid int32, out *[2]int32, bytes int32) int32 {
				if pgid != leader || bytes != 8 {
					t.Fatal("unexpected Darwin group query")
				}
				*out = tc.members
				return tc.count
			})
			if got != tc.want {
				t.Fatalf("group confirmation = %v, want %v", got, tc.want)
			}
		})
	}
	if onlyObservedDarwinGroupLeader(leader, nil) {
		t.Fatal("missing Darwin group inventory cleared a signal failure")
	}
}

func TestDarwinRetryRequiresExactWaitableChild(t *testing.T) {
	const leader, parent = 12345, 23456
	info := unix.KinfoProc{
		Proc:  unix.ExternProc{P_pid: leader, P_stat: 5},
		Eproc: unix.Eproc{Ppid: parent, Pgid: leader},
	}
	if !darwinWaitableGroupLeader(&info, leader, parent) {
		t.Fatal("waitable direct group leader refused")
	}
	if darwinWaitableGroupLeader(nil, leader, parent) ||
		darwinWaitableGroupLeader(&info, leader+1, parent) ||
		darwinWaitableGroupLeader(&info, leader, parent+1) {
		t.Fatal("missing or different child identity was accepted")
	}
	info.Eproc.Pgid = leader + 1
	if darwinWaitableGroupLeader(&info, leader, parent) {
		t.Fatal("foreign process group was accepted")
	}
	info.Eproc.Pgid = leader
	info.Proc.P_stat = 2
	if darwinWaitableGroupLeader(&info, leader, parent) {
		t.Fatal("live child was accepted as waitable")
	}
}

func TestDarwinCleanupRetryWaitsForExistingObserver(t *testing.T) {
	attempted := make(chan struct{})
	owner := &ownedProcess{
		pid:             os.Getpid(), // The injected signal function never signals this process.
		faulted:         make(chan struct{}),
		signalClosed:    make(chan struct{}),
		retryReady:      make(chan struct{}),
		observationDone: make(chan struct{}),
		nativeSignal: func(_ int, _ syscall.Signal, observed bool) error {
			if !observed {
				close(attempted)
				return syscall.EPERM
			}
			return os.ErrProcessDone
		},
	}
	owner.faultLocked(ErrProcessCleanupPending)
	finished := make(chan error, 1)
	go func() { finished <- owner.retryCleanup() }()
	select {
	case <-attempted:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup retry did not attempt the owned group")
	}
	owner.mu.Lock()
	owner.exitObserved = true
	owner.finalBlocked = true
	close(owner.observationDone)
	owner.mu.Unlock()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("cleanup retry returned before its exact exit observation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup retry did not consume the existing observation")
	}
	select {
	case <-owner.retryReady:
	default:
		t.Fatal("verified cleanup did not release the consuming wait")
	}
}
