package servicehost

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

const (
	serviceStateStopped      uint32 = 1
	serviceStateStartPending uint32 = 2
	serviceStateStopPending  uint32 = 3
	serviceStateRunning      uint32 = 4
)

// The platform binds these operations to one prepared process owner and one
// actual command. Bind follows successful Start and precedes the sole Wait.
// A failed Bind owns safe parent cleanup; this protocol must still drain Wait.
// Close is admitted only after Wait and any explicit cancellation have returned.
// These operations are private composition, not an alternate native authority.
type serviceChildOperations struct {
	start, bind, wait, cancel, close func() error
}

type serviceChildResult struct {
	started, stopRequested bool
	waitErr                error // Actual command wait, even for an accepted stop.
	err                    error // Service outcome, including lifecycle and I/O faults.
}

// Cmd.Wait may prefer a process ExitError over its output-copy error. Retain
// writer failures separately so accepted manual termination cannot erase them.
type serviceCommandOutput struct {
	writer io.Writer
	mu     sync.Mutex
	err    error
}

func (w *serviceCommandOutput) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.mu.Lock()
		if w.err == nil {
			w.err = err
		}
		w.mu.Unlock()
	}
	return n, err
}

func waitServiceCommandOutput(wait func() error, output *serviceCommandOutput) error {
	err := wait()
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.err != nil {
		return errors.Join(err, output.err)
	}
	return err // Preserve a plain ExitError when no output failure was observed.
}

// runServiceChild retains the owner and log through the actual command wait and
// admitted cancellation. Its three-second interval diagnoses pending work; it
// cannot complete the service or close resources on behalf of that work.
func runServiceChild(stop <-chan struct{}, child serviceChildOperations, status func(state, checkpoint, exit uint32) error, log io.WriteCloser) (result serviceChildResult) {
	var statusErr error
	publish := func(state, checkpoint, exit uint32) error {
		err := status(state, checkpoint, exit)
		if statusErr == nil {
			statusErr = err
		}
		return err
	}
	finish := func() {
		result.err = errors.Join(result.err, statusErr, child.close())
		if result.err != nil {
			message := fmt.Sprintln(result.err)
			n, err := io.WriteString(log, message)
			if err == nil && n != len(message) {
				err = io.ErrShortWrite
			}
			result.err = errors.Join(result.err, err)
		}
		result.err = errors.Join(result.err, log.Close())
		exit := uint32(0)
		if result.err != nil {
			exit = 1
		}
		// Neither log nor native owner remains live when STOPPED is attempted.
		result.err = errors.Join(result.err, publish(serviceStateStopped, 0, exit))
	}
	if err := child.start(); err != nil {
		result.err = err
		finish()
		return result
	}
	result.started = true
	bindErr := child.bind()
	result.err = bindErr
	waitDone := make(chan error, 1)
	go func() { waitDone <- child.wait() }()

	var cancelDone <-chan error
	waited, canceled := false, true
	var interval *time.Ticker
	var tick <-chan time.Time
	var checkpoint uint32
	beginPending := func(manual, cancel bool) {
		result.stopRequested = manual
		stop = nil
		checkpoint = 1
		_ = publish(serviceStateStopPending, checkpoint, 0)
		interval = time.NewTicker(3 * time.Second)
		tick = interval.C
		if cancel {
			canceled = false
			done := make(chan error, 1)
			cancelDone = done
			go func() { done <- child.cancel() }()
		}
	}
	if bindErr != nil {
		// Bind failure has already refused helper admission and attempted exact
		// parent cleanup. It is an accepted launch and still requires real Wait.
		beginPending(false, false)
	} else if publish(serviceStateRunning, 0, 0) != nil {
		// A feedback failure cannot abandon an accepted child.
		beginPending(false, true)
	}
	defer func() {
		if interval != nil {
			interval.Stop()
		}
	}()
	noticed := false
	observeWait := func(err error) {
		result.waitErr = err
		waited = true
		waitDone = nil
	}
	for !waited || !canceled {
		// Prefer an already observed natural completion over a late stop request.
		if !waited {
			select {
			case err := <-waitDone:
				observeWait(err)
			default:
			}
		}
		if waited && canceled {
			break
		}
		select {
		case err := <-waitDone:
			observeWait(err)
		case <-stop:
			select {
			case err := <-waitDone:
				observeWait(err)
			default:
				beginPending(true, true)
			}
		case err := <-cancelDone:
			result.err = errors.Join(result.err, err)
			canceled = true
			cancelDone = nil
		case <-tick:
			checkpoint++
			if checkpoint == 0 {
				checkpoint = 1
			}
			_ = publish(serviceStateStopPending, checkpoint, 0)
			if !noticed {
				noticed = true
				const notice = "Service shutdown is not confirmed; waiting for the owned command and output drain.\n"
				n, err := io.WriteString(log, notice)
				if err == nil && n != len(notice) {
					err = io.ErrShortWrite
				}
				result.err = errors.Join(result.err, err)
			}
		}
	}
	// An accepted manual stop keeps its original service classification while
	// preserving the actual process exit. Only a plain ExitError is expected;
	// wait/copy failures and joined failures remain service errors.
	if _, exit := result.waitErr.(*exec.ExitError); !result.stopRequested || !exit {
		result.err = errors.Join(result.err, result.waitErr)
	}
	finish()
	return result
}
