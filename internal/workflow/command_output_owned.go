package workflow

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type ownedWorkflowOutput struct {
	file     *os.File
	once     sync.Once
	closeErr error
	copyErr  error
	done     chan struct{}
}

func (output *ownedWorkflowOutput) close() error {
	output.once.Do(func() { output.closeErr = output.file.Close() })
	return output.closeErr
}

// Unlike Cmd's internal copier, every output descriptor Close is observed.
// A timer can end output admission, never abandon a blocked Write/Close/copy.
func runWorkflowCommandWithOutput(cmd *exec.Cmd, owner commandOwner, writer io.Writer) (observation commandRunObservation, outputClosed bool, failure error) {
	outR, outW, err := os.Pipe()
	if err != nil {
		return observation, false, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		return observation, false, errors.Join(err, outR.Close(), outW.Close())
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return observation, false, errors.Join(err, outR.Close(), outW.Close(), errR.Close(), errW.Close())
	}
	input := cmd.Stdin
	if input == nil {
		input = strings.NewReader("")
	}
	cmd.Stdin = inR
	inputOwner := &ownedWorkflowOutput{file: inW, done: make(chan struct{})}
	outputs := []*ownedWorkflowOutput{{file: outR, done: make(chan struct{})}, {file: errR, done: make(chan struct{})}}
	cmd.Stdout = outW
	cmd.Stderr = errW
	if err = cmd.Start(); err != nil {
		var ownerErr error
		if owner != nil {
			ownerErr = owner.Close()
		}
		return observation, false, errors.Join(err, outR.Close(), outW.Close(), errR.Close(), errW.Close(), inR.Close(), inW.Close(), workflowFailure(ErrWorkflowCleanup, ownerErr))
	}
	observation.Accepted = true
	writerCloseErr := errors.Join(outW.Close(), errW.Close(), inR.Close())
	var bindErr error
	if owner != nil {
		bindErr = owner.Bind(cmd.Process)
	}
	observation.Bound = bindErr == nil
	outputFailed := make(chan struct{}, len(outputs))
	for _, output := range outputs {
		go func(output *ownedWorkflowOutput) {
			defer close(output.done)
			copyErr := copyWorkflowOutput(writer, output.file)
			if copyErr != nil {
				outputFailed <- struct{}{}
			}
			output.copyErr = errors.Join(copyErr, output.close())
		}(output)
	}
	go func() {
		defer close(inputOwner.done)
		inputOwner.copyErr = errors.Join(copyWorkflowOutput(inW, input), inputOwner.close())
	}()
	cancel := cmd.Cancel
	if cancel == nil {
		cancel = cmd.Process.Kill
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	var waitErr, cancelErr error
	select {
	case waitErr = <-waitDone:
	case <-outputFailed:
		// A log failure ends worker execution but does not transfer ownership.
		// If Wait already completed, there is no need to invoke the helper.
		select {
		case waitErr = <-waitDone:
		default:
			if bindErr == nil {
				cancelErr = cancel()
				if errors.Is(cancelErr, os.ErrProcessDone) {
					cancelErr = nil
				}
			}
			waitErr = <-waitDone
		}
	}
	observation.Waited = cmd.ProcessState != nil
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	timedOut := false
	for _, output := range outputs {
		select {
		case <-output.done:
		case <-timer.C:
			timedOut = true
			for _, pending := range outputs {
				_ = pending.close()
			}
			<-output.done
		}
		if timedOut {
			for _, pending := range outputs {
				<-pending.done
			}
			break
		}
	}
	<-inputOwner.done
	var outputErr error
	outputErr = errors.Join(outputErr, inputOwner.copyErr, inputOwner.closeErr)
	for _, output := range outputs {
		outputErr = errors.Join(outputErr, output.copyErr, output.closeErr)
	}
	if timedOut {
		outputErr = errors.Join(outputErr, exec.ErrWaitDelay)
	}
	outputErr = errors.Join(outputErr, writerCloseErr)
	var ownerErr error
	if owner != nil {
		ownerErr = owner.Close()
	}
	observation.OwnerClosed = ownerErr == nil
	outputClosed = outputErr == nil
	if !observation.Waited {
		waitErr = errors.Join(waitErr, workflowFailure(ErrWorkflowCleanup, ErrWorkflowCleanup))
	}
	return observation, outputClosed, errors.Join(waitErr, workflowFailure(ErrWorkflowCleanup, errors.Join(bindErr, cancelErr, ownerErr)), workflowFailure(ErrWorkflowPersistence, outputErr))
}
func copyWorkflowOutput(writer io.Writer, reader io.Reader) error {
	_, err := io.Copy(writer, reader)
	return err
}
