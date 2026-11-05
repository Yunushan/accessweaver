package servicehost

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests exercise the private service composition with controlled operation
// barriers. They do not run SCM, a Windows termination helper or a native child.
// The Windows source binds every operation to one real Cmd and TreeOwner.
type serviceProtocolLog struct {
	mu       sync.Mutex
	data     bytes.Buffer
	closed   bool
	short    bool
	writeErr error
	closeErr error
	onClose  func()
}

func (l *serviceProtocolLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, errors.New("service fixture log written after close")
	}
	if l.writeErr != nil {
		return 0, l.writeErr
	}
	if l.short {
		return len(data) - 1, nil
	}
	return l.data.Write(data)
}
func (l *serviceProtocolLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("service fixture log closed twice")
	}
	l.closed = true
	if l.onClose != nil {
		l.onClose()
	}
	return l.closeErr
}
func (l *serviceProtocolLog) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}
func (l *serviceProtocolLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.data.String()
}

func awaitServiceProtocol(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal(message)
	}
}

func TestServicePendingBudgetRetainsWaitOwnerAndLog(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "diagnostic-only", true: "short-notice"}[short], func(t *testing.T) {
			stop, waitEntered, cancelEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
			releaseWait, releaseCancel := make(chan struct{}), make(chan struct{})
			waitReturned, pendingAgain, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var stopOnce, waitOnce, cancelOnce sync.Once
			unblock := func() {
				stopOnce.Do(func() { close(stop) })
				waitOnce.Do(func() { close(releaseWait) })
				cancelOnce.Do(func() { close(releaseCancel) })
			}
			t.Cleanup(func() { unblock(); awaitServiceProtocol(t, returned, "service protocol fixture did not join") })
			var bound, ownerClosed, logClosed, stopped atomic.Bool
			var waitCalls, cancelCalls, ownerCloses, pendingCalls atomic.Int32
			log := &serviceProtocolLog{short: short, onClose: func() {
				if !ownerClosed.Load() {
					t.Error("service log closed before native owner")
				}
				logClosed.Store(true)
			}}
			exit := &exec.ExitError{} // Synthetic status, never a native wait claim.
			child := serviceChildOperations{
				start: func() error { return nil },
				bind:  func() error { bound.Store(true); return nil },
				wait: func() error {
					waitCalls.Add(1)
					if !bound.Load() {
						t.Error("service began Wait before actual handle binding")
					}
					close(waitEntered)
					<-releaseWait
					close(waitReturned)
					return exit
				},
				cancel: func() error {
					cancelCalls.Add(1)
					close(cancelEntered)
					<-releaseCancel
					return nil
				},
				close: func() error {
					ownerCloses.Add(1)
					select {
					case <-waitReturned:
					default:
						t.Error("service closed owner before actual Wait returned")
					}
					select {
					case <-releaseCancel:
					default:
						t.Error("service closed owner with cancellation still admitted")
					}
					ownerClosed.Store(true)
					return nil
				},
			}
			status := func(state, checkpoint, serviceExit uint32) error {
				switch state {
				case serviceStateStopPending:
					pendingCalls.Add(1)
					if serviceExit != 0 || checkpoint == 0 || stopped.Load() {
						t.Error("service pending status claimed a terminal result")
					}
					if checkpoint == 2 {
						close(pendingAgain)
					}
				case serviceStateStopped:
					if !ownerClosed.Load() || !logClosed.Load() {
						t.Error("STOPPED preceded owner or log closure")
					}
					stopped.Store(true)
				}
				return nil
			}
			var result serviceChildResult
			go func() { defer close(returned); result = runServiceChild(stop, child, status, log) }()
			awaitServiceProtocol(t, waitEntered, "service did not enter sole Wait")
			stopOnce.Do(func() { close(stop) })
			awaitServiceProtocol(t, cancelEntered, "service did not admit one stop operation")
			// Use the real unchanged three-second interval, with both operations
			// deliberately held. A checkpoint is diagnostic, never exit proof.
			awaitServiceProtocol(t, pendingAgain, "service pending budget had no progress feedback")
			if ownerClosed.Load() || log.isClosed() || stopped.Load() {
				t.Fatal("service timeout released live operation ownership")
			}
			select {
			case <-returned:
				t.Fatal("service timeout substituted for actual Wait")
			default:
			}
			waitOnce.Do(func() { close(releaseWait) })
			awaitServiceProtocol(t, waitReturned, "service actual Wait did not return")
			select {
			case <-returned:
				t.Fatal("actual Wait bypassed a still-admitted termination helper")
			default:
			}
			if ownerClosed.Load() || log.isClosed() {
				t.Fatal("service released owner or log before termination completed")
			}
			cancelOnce.Do(func() { close(releaseCancel) })
			awaitServiceProtocol(t, returned, "service did not join actual operation completion")
			if !result.started || !result.stopRequested || result.waitErr != exit || waitCalls.Load() != 1 || cancelCalls.Load() != 1 || ownerCloses.Load() != 1 || pendingCalls.Load() < 2 || !stopped.Load() {
				t.Fatal("service lost actual exit or duplicated lifecycle operations")
			}
			if short {
				if !errors.Is(result.err, io.ErrShortWrite) {
					t.Fatal("short waiting notice did not remain a service failure")
				}
			} else if result.err != nil || !bytes.Contains([]byte(log.text()), []byte("waiting for the owned command")) {
				t.Fatal("diagnostic pending interval became terminal failure")
			}
		})
	}
}

func TestServiceAcceptedLaunchAndResourceFaultsRemainObservable(t *testing.T) {
	startErr := errors.New("fixture start error")
	bindErr := errors.New("fixture accepted bind uncertainty")
	waitErr := errors.New("fixture actual wait or output error")
	cancelErr := errors.New("fixture cancellation uncertainty")
	ownerErr := errors.New("fixture owner close error")
	writeErr := errors.New("fixture log write error")
	logErr := errors.New("fixture log close error")
	feedbackErr := errors.New("fixture SCM feedback error")
	for _, item := range []struct {
		name                                                    string
		start, bind, wait, cancel                               error
		owner, write, log, feedback                             error
		manual, runningFault, pendingFault, stoppedFault, short bool
		want                                                    error
	}{
		{name: "failed-start", start: startErr, want: startErr},
		{name: "accepted-bind-failure-still-waits", bind: bindErr, wait: waitErr, want: bindErr},
		{name: "natural-exit-failure", wait: waitErr, want: waitErr},
		{name: "manual-exit-observed", manual: true, wait: &exec.ExitError{}},
		{name: "manual-output-failure", manual: true, wait: waitErr, want: waitErr},
		{name: "termination-failure", manual: true, cancel: cancelErr, want: cancelErr},
		{name: "owner-close-failure", owner: ownerErr, want: ownerErr},
		{name: "error-log-write-failure", wait: waitErr, write: writeErr, want: writeErr},
		{name: "error-log-short-write", wait: waitErr, short: true, want: io.ErrShortWrite},
		{name: "log-close-failure", log: logErr, want: logErr},
		{name: "running-feedback-failure-stops-and-drains", runningFault: true, feedback: feedbackErr, want: feedbackErr},
		{name: "pending-feedback-failure-still-drains", manual: true, pendingFault: true, feedback: feedbackErr, want: feedbackErr},
		{name: "stopped-feedback-failure", stoppedFault: true, feedback: feedbackErr, want: feedbackErr},
	} {
		t.Run(item.name, func(t *testing.T) {
			stop := make(chan struct{})
			if item.manual {
				close(stop)
			}
			var starts, binds, waits, cancels, closes atomic.Int32
			var ownerClosed atomic.Bool
			cancelReturned := make(chan struct{})
			var cancelOnce sync.Once
			log := &serviceProtocolLog{short: item.short, writeErr: item.write, closeErr: item.log, onClose: func() {
				if !ownerClosed.Load() {
					t.Error("log close preceded owner close")
				}
			}}
			child := serviceChildOperations{
				start: func() error { starts.Add(1); return item.start },
				bind:  func() error { binds.Add(1); return item.bind },
				wait: func() error {
					waits.Add(1)
					if binds.Load() != 1 {
						t.Error("Wait did not follow binding")
					}
					if item.manual || item.runningFault {
						<-cancelReturned
					}
					return item.wait
				},
				cancel: func() error {
					cancels.Add(1)
					cancelOnce.Do(func() { close(cancelReturned) })
					return item.cancel
				},
				close: func() error { closes.Add(1); ownerClosed.Store(true); return item.owner },
			}
			var stopped uint32
			status := func(state, checkpoint, exit uint32) error {
				if state == serviceStateStopped {
					stopped++
					if !ownerClosed.Load() || !log.isClosed() {
						t.Error("STOPPED preceded owned-resource closure")
					}
				}
				if (item.runningFault && state == serviceStateRunning) || (item.pendingFault && state == serviceStateStopPending) || (item.stoppedFault && state == serviceStateStopped) {
					return item.feedback
				}
				return nil
			}
			result := runServiceChild(stop, child, status, log)
			if item.want != nil && !errors.Is(result.err, item.want) {
				t.Fatal("service lost an owned-operation or feedback error")
			}
			if item.want == nil && result.err != nil {
				t.Fatal("accepted manual exit lost service-stop classification")
			}
			if starts.Load() != 1 || closes.Load() != 1 || stopped != 1 {
				t.Fatal("service lifecycle was repeated or not finalized")
			}
			if item.start != nil {
				if result.started || binds.Load() != 0 || waits.Load() != 0 || cancels.Load() != 0 {
					t.Fatal("failed Start was treated as accepted launch")
				}
			} else if !result.started || binds.Load() != 1 || waits.Load() != 1 || result.waitErr != item.wait {
				t.Fatal("accepted launch lost binding or actual Wait observation")
			}
			if item.bind != nil {
				if cancels.Load() != 0 || !errors.Is(result.err, waitErr) {
					t.Fatal("failed binding admitted another helper or hid actual Wait failure")
				}
			} else if item.manual || item.runningFault {
				if cancels.Load() != 1 {
					t.Fatal("service did not admit exactly one cancellation")
				}
			} else if cancels.Load() != 0 {
				t.Fatal("natural exit invoked tree cleanup")
			}
		})
	}
}

// The output copy and selected process exit are controlled composition here,
// not native Wait evidence. The first write fails but later writes and Close
// succeed, so the separately retained writer observation is the only I/O proof.
func TestServiceManualExitRetainsIntermittentOutputFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "write-error", true: "short-write"}[short], func(t *testing.T) {
			cause := errors.New("intermittent fixture output error")
			underlying := &serviceProtocolLog{writeErr: cause, short: short}
			if short {
				underlying.writeErr = nil
				cause = io.ErrShortWrite
			}
			output := &serviceCommandOutput{writer: underlying}
			if _, err := output.Write([]byte("first child output")); !errors.Is(err, cause) {
				t.Fatal("output observer changed the first write failure")
			}
			underlying.mu.Lock()
			underlying.writeErr, underlying.short = nil, false
			underlying.mu.Unlock()
			if n, err := output.Write([]byte("later output")); err != nil || n != len("later output") {
				t.Fatal("output observer prevented later successful writes")
			}
			stop, canceled := make(chan struct{}), make(chan struct{})
			close(stop)
			exit := &exec.ExitError{} // Synthetic selected Wait result.
			child := serviceChildOperations{
				start: func() error { return nil }, bind: func() error { return nil },
				wait: func() error {
					<-canceled
					return waitServiceCommandOutput(func() error { return exit }, output)
				},
				cancel: func() error { close(canceled); return nil }, close: func() error { return nil },
			}
			result := runServiceChild(stop, child, func(uint32, uint32, uint32) error { return nil }, underlying)
			var retained *exec.ExitError
			if !result.stopRequested || !errors.Is(result.err, cause) || !errors.As(result.waitErr, &retained) || retained != exit || !errors.Is(result.waitErr, cause) || !underlying.isClosed() {
				t.Fatal("manual process exit erased intermittent child output failure")
			}
		})
	}
	output := &serviceCommandOutput{writer: io.Discard}
	exit := &exec.ExitError{}
	if got := waitServiceCommandOutput(func() error { return exit }, output); got != exit {
		t.Fatal("clean output observer changed plain ExitError classification")
	}
}
