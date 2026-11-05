//go:build !windows

package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
)

type exitObserver interface {
	bind(int) error
	waitExit() error
	close() error
}
type ownerPhase uint8

const (
	ownerRunning ownerPhase = iota
	ownerReaping
	ownerDone
	ownerLost
)

type lifetimeFault struct{ err error }

// No consumer of child status may run outside this owner. In particular the
// application must not replace SIGCHLD with SIG_IGN/SA_NOCLDWAIT or run a
// wildcard reaper. The ordinary Go runtime retains waitable child status.
type ownedProcess struct {
	mu              sync.Mutex
	cmd             *exec.Cmd
	pid             int
	phase           ownerPhase
	observer        exitObserver
	fault           atomic.Pointer[lifetimeFault]
	faultOnce       sync.Once
	faulted         chan struct{}
	signalClosed    chan struct{}
	closeOnce       sync.Once
	retryReady      chan struct{}
	finalBlocked    bool
	retryAuthorized bool
	lifecycleErr    error
	onFault         func(error)
	// Private per-instance native/test seams, fixed before Start. Neither can
	// substitute a PID, consume child status, or alter signal admission.
	nativeSignal     func(int, syscall.Signal) error
	beforeWait       func()
	admittedDispatch func(int, func() error) error
}

func ownedProcessGone(err error) bool {
	return errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH)
}

func prepareProcessLifetime(cmd *exec.Cmd) (processLifetime, error) {
	observer, err := newExitObserver()
	if err != nil {
		return nil, err
	}
	return &ownedProcess{cmd: cmd, observer: observer, faulted: make(chan struct{}), signalClosed: make(chan struct{}), retryReady: make(chan struct{}), nativeSignal: nativeGroupSignal}, nil
}
func (o *ownedProcess) setFaultHandler(handler func(error)) { o.onFault = handler }
func (o *ownedProcess) pendingError() error {
	if fault := o.fault.Load(); fault != nil {
		return fault.err
	}
	return nil
}
func (o *ownedProcess) faultSignal() <-chan struct{} { return o.faulted }
func (o *ownedProcess) abortStart() error            { return o.observer.close() }
func (o *ownedProcess) captureLocked() bool {
	if o.pid == 0 && o.cmd.Process != nil {
		o.pid = o.cmd.Process.Pid
	}
	return o.pid > 1
}
func (o *ownedProcess) closeSignalsLocked() { o.closeOnce.Do(func() { close(o.signalClosed) }) }
func (o *ownedProcess) faultLocked(err error) {
	o.lifecycleErr = ErrProcessLifecycle
	if errors.Is(err, ErrProcessOwnershipLost) {
		o.phase = ownerLost
		o.closeSignalsLocked()
		o.fault.Store(&lifetimeFault{ErrProcessOwnershipLost})
	} else if o.fault.Load() == nil {
		o.fault.Store(&lifetimeFault{ErrProcessCleanupPending})
	}
	o.faultOnce.Do(func() { close(o.faulted) })
}
func (o *ownedProcess) notifyFault() {
	if err := o.pendingError(); err != nil && o.onFault != nil {
		o.onFault(err)
	}
}
func (o *ownedProcess) dispatch(signal func(*os.Process) error) error {
	if err := o.pendingError(); err != nil {
		return err
	}
	o.mu.Lock()
	if o.phase == ownerLost {
		o.mu.Unlock()
		return ErrProcessOwnershipLost
	}
	if o.phase != ownerRunning {
		o.mu.Unlock()
		return os.ErrProcessDone
	}
	if !o.captureLocked() {
		o.faultLocked(ErrProcessOwnershipLost)
		o.mu.Unlock()
		o.notifyFault()
		return ErrProcessOwnershipLost
	}
	if err := o.pendingError(); err != nil {
		o.mu.Unlock()
		return err
	}
	// Copy only immutable Pid, so callbacks cannot mutate cmd.Process. The
	// production callbacks signal only; private test callbacks must never consume
	// child status or release ownership. Native dispatch uses captured identity.
	view := &os.Process{Pid: o.pid}
	err := o.callSignalLocked(func() error { return signal(view) })
	failed := err != nil && !ownedProcessGone(err)
	if failed {
		if errors.Is(err, ErrProcessOwnershipLost) || errors.Is(err, syscall.ECHILD) {
			o.faultLocked(ErrProcessOwnershipLost)
		} else {
			o.faultLocked(ErrProcessCleanupPending)
		}
	}
	// Retain this call's resolved result even if an explicit retry completes
	// the lifetime and clears the nonterminal fault immediately after unlock.
	if failed {
		err = o.pendingError()
	}
	o.mu.Unlock()
	o.notifyFault()
	return err
}
func (o *ownedProcess) callSignalLocked(invoke func() error) error {
	if o.admittedDispatch != nil {
		return o.admittedDispatch(o.pid, invoke)
	}
	return invoke()
}
func (o *ownedProcess) policySignal() {
	if o.pendingError() != nil {
		return
	}
	o.mu.Lock()
	if o.phase != ownerRunning || o.pendingError() != nil {
		o.mu.Unlock()
		return
	}
	if !o.captureLocked() {
		o.faultLocked(ErrProcessOwnershipLost)
		o.mu.Unlock()
		o.notifyFault()
		return
	}
	err := o.callSignalLocked(func() error { return o.nativeSignal(o.pid, syscall.SIGKILL) })
	if err != nil && !ownedProcessGone(err) {
		if errors.Is(err, ErrProcessOwnershipLost) || errors.Is(err, syscall.ECHILD) {
			o.faultLocked(ErrProcessOwnershipLost)
		} else {
			o.faultLocked(ErrProcessCleanupPending)
		}
	}
	o.mu.Unlock()
	o.notifyFault()
}
func (o *ownedProcess) retireLocked() { o.phase = ownerReaping; o.closeSignalsLocked() }

// RetryCleanup is explicit and generation-bound at Manager. It never retries
// lost ownership, never consumes status and never reopens retired admission.
func (o *ownedProcess) retryCleanup() error {
	if err := o.pendingError(); errors.Is(err, ErrProcessOwnershipLost) {
		return err
	}
	o.mu.Lock()
	if o.phase == ownerLost {
		o.mu.Unlock()
		return ErrProcessOwnershipLost
	}
	if o.phase != ownerRunning {
		o.mu.Unlock()
		return os.ErrProcessDone
	}
	if o.pendingError() == nil {
		o.mu.Unlock()
		return ErrRunUnavailable
	}
	if !o.captureLocked() {
		o.faultLocked(ErrProcessOwnershipLost)
		o.mu.Unlock()
		o.notifyFault()
		return ErrProcessOwnershipLost
	}
	err := o.callSignalLocked(func() error { return o.nativeSignal(o.pid, syscall.SIGKILL) })
	if err != nil && !ownedProcessGone(err) {
		if errors.Is(err, ErrProcessOwnershipLost) || errors.Is(err, syscall.ECHILD) {
			o.faultLocked(ErrProcessOwnershipLost)
			o.mu.Unlock()
			o.notifyFault()
			return ErrProcessOwnershipLost
		}
		o.mu.Unlock()
		return ErrProcessCleanupPending
	}
	if o.finalBlocked {
		o.retireLocked()
		close(o.retryReady)
	} else {
		// Observer remains owned/in flight. After the successful explicit force,
		// its first final group-cleanup attempt may proceed; keep sticky lifecycle.
		o.retryAuthorized = true
	}
	o.mu.Unlock()
	return nil
}
func (o *ownedProcess) wait(ctx context.Context) (waitErr, lifecycleErr error) {
	o.mu.Lock()
	valid := o.captureLocked()
	if !valid {
		o.faultLocked(ErrProcessOwnershipLost)
	}
	pid := o.pid
	o.mu.Unlock()
	if !valid {
		o.notifyFault()
		select {}
	}
	policyDone := make(chan struct{})
	go func() {
		defer close(policyDone)
		select {
		case <-ctx.Done():
			o.policySignal()
		case <-o.signalClosed:
		}
	}()
	observeErr := o.observer.bind(pid)
	if observeErr == nil {
		observeErr = o.observer.waitExit()
	}
	o.mu.Lock()
	if errors.Is(observeErr, syscall.ECHILD) || errors.Is(observeErr, ErrProcessOwnershipLost) {
		o.faultLocked(ErrProcessOwnershipLost)
	} else if observeErr != nil {
		// A failed observation is not an exit proof. Exclusive ownership is
		// still retained, so force the original private group before the sole
		// consuming wait, and retain lifecycle uncertainty in its result.
		o.lifecycleErr = ErrProcessLifecycle
	}
	if o.phase == ownerLost {
		o.mu.Unlock()
		o.notifyFault()
		<-policyDone
		// There is no safe numeric-PID recovery from a foreign consuming reap.
		// Retain the owner and all resources, with Done pending; issue no syscall.
		select {}
	}
	if o.pendingError() != nil && !o.retryAuthorized {
		o.finalBlocked = true
		o.mu.Unlock()
		o.notifyFault()
		<-o.retryReady
	} else {
		err := o.callSignalLocked(func() error { return o.nativeSignal(pid, syscall.SIGKILL) })
		if err != nil && !ownedProcessGone(err) {
			o.finalBlocked = true
			if errors.Is(err, ErrProcessOwnershipLost) || errors.Is(err, syscall.ECHILD) {
				o.faultLocked(ErrProcessOwnershipLost)
			} else {
				o.faultLocked(ErrProcessCleanupPending)
			}
			o.mu.Unlock()
			o.notifyFault()
			<-o.retryReady
		} else {
			o.retireLocked()
			o.mu.Unlock()
		}
	}
	// signalClosed was closed under the same mutex that brackets every admitted
	// call. No native group signal can overlap the consuming wait or I/O drain.
	<-policyDone
	if o.beforeWait != nil {
		o.beforeWait()
	}
	waitErr = o.cmd.Wait()
	closeErr := o.observer.close()
	o.mu.Lock()
	if closeErr != nil {
		o.lifecycleErr = ErrProcessLifecycle
	}
	o.phase = ownerDone
	lifecycleErr = o.lifecycleErr
	o.fault.Store(nil)
	o.mu.Unlock()
	return waitErr, lifecycleErr
}
