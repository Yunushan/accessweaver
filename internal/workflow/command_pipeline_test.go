package workflow

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const workflowPipelineChildArgument = "--workflow-pipeline-source-v1"

// This inert source child only reads a bounded anonymous stdin frame, creates
// its exclusive synthetic report and emits fixed stdout/stderr. It never
// starts a vendor program or performs a Windows workflow.
func TestWorkflowCommandPipelineSourceChild(t *testing.T) {
	marker := -1
	for index, argument := range os.Args {
		if argument == "--" {
			marker = index
			break
		}
	}
	if marker < 0 {
		t.Skip("source pipeline child requires its closed fixture arguments")
	}
	if len(os.Args[marker+1:]) != 2 || os.Args[marker+1] != workflowPipelineChildArgument {
		os.Exit(90)
	}
	os.Exit(workflowPipelineChild(os.Args[marker+2]))
}

func workflowPipelineChild(mode string) int {
	if mode != "complete" && mode != "cancel" && mode != "wrong-token" && mode != "output-failure" {
		return 91
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, (64<<10)+1))
	if err != nil || len(input) > 64<<10 {
		return 92
	}
	var frame map[string]json.RawMessage
	if json.Unmarshal(input, &frame) != nil {
		return 92
	}
	var resultPath, token string
	if json.Unmarshal(frame["resultPath"], &resultPath) != nil || json.Unmarshal(frame["resultToken"], &token) != nil || !filepath.IsAbs(resultPath) || filepath.Base(resultPath) != "result.json" || !historyHex(token, 48) {
		return 92
	}
	if mode == "wrong-token" {
		// Flip one known valid token digit; do not rely on random inequality.
		if token[0] == '0' {
			token = "1" + token[1:]
		} else {
			token = "0" + token[1:]
		}
	}
	body, err := json.Marshal(map[string]any{"ok": true, "reportVersion": workerReportVersion, "resultToken": token, "data": map[string]any{"sourcePipeline": true}})
	if err != nil {
		return 93
	}
	file, err := os.OpenFile(resultPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 93
	}
	n, writeErr := file.Write(body)
	if n != len(body) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if errors.Join(writeErr, syncErr, closeErr) != nil {
		return 93
	}
	if _, err = io.WriteString(os.Stdout, "source-pipeline-stdout\n"); err != nil {
		return 94
	}
	if mode == "output-failure" {
		// Write exactly once, then remain alive without relying on either pipe.
		time.Sleep(30 * time.Second)
		return 95
	}
	if _, err = io.WriteString(os.Stderr, "source-pipeline-stderr\n"); err != nil {
		return 94
	}
	if mode == "cancel" {
		// The parent observes the stdout marker through its owned process.log
		// only after this checked report Write/Sync/Close, then cancels its
		// owned CommandContext before this bounded backstop. This does not
		// model completion of any native/vendor side effect.
		<-time.After(30 * time.Second)
		return 95
	}
	return 0
}

func workflowPipelineCommand(ctx context.Context, input []byte, mode string) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestWorkflowCommandPipelineSourceChild$", "--", workflowPipelineChildArgument, mode)
	cmd.Stdin = bytes.NewReader(append([]byte(nil), input...))
	return cmd, nil
}

func workflowPipelineBind(t *testing.T, f *workflowShutdownFixture, mode string) (**exec.Cmd, **localExecutionObservation, *[]byte) {
	t.Helper()
	var command *exec.Cmd
	var observation *localExecutionObservation
	var input []byte
	f.manager.execute = func(ctx context.Context, dir string, request Request) (json.RawMessage, error) {
		observation = localExecutionFrom(ctx)
		return executeWorkflow(ctx, dir, request, func(ctx context.Context, frame []byte, program string) (*exec.Cmd, error) {
			if len(program) == 0 || !strings.Contains(program, "resultToken") {
				return nil, errors.New("source pipeline program was absent")
			}
			input = append([]byte(nil), frame...)
			var err error
			command, err = workflowPipelineCommand(ctx, frame, mode)
			return command, err
		})
	}
	return &command, &observation, &input
}

func workflowPipelineObserved(t *testing.T, command *exec.Cmd, observation *localExecutionObservation, reportValid bool) {
	t.Helper()
	if command == nil || command.ProcessState == nil || observation == nil || observation.NoNativeOwners || observation.NeverCalled || !observation.Invoked || !observation.Setup || !observation.Waited || !observation.Bound || !observation.OwnerClosed || !observation.OutputClosed || observation.ReportValid != reportValid || !observation.Finished {
		t.Fatal("source pipeline did not retain actual command, output and report observations")
	}
}

func TestWorkflowCommandPipelineRealCleanExitAndLocalAcknowledgement(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	command, observation, input := workflowPipelineBind(t, f, "complete")
	job := f.start()
	workflowLifecycleAwait(t, f.manager)
	workflowPipelineObserved(t, *command, *observation, true)
	if !(*command).ProcessState.Success() || f.manager.TerminalError(job.ID) != nil || f.manager.Snapshot().State != "succeeded" {
		t.Fatal("clean actual source pipeline became an execution failure")
	}
	var frame struct {
		ResultPath  string
		ResultToken string
	}
	if json.Unmarshal(*input, &frame) != nil || frame.ResultPath != filepath.Join(f.manager.root, job.ID, "result.json") || !historyHex(frame.ResultToken, 48) {
		t.Fatal("pipeline constructor did not receive the immutable correlated request")
	}
	if token, err := hex.DecodeString(frame.ResultToken); err != nil || len(token) != 24 {
		t.Fatal("pipeline request token was invalid")
	}
	raw, err := os.ReadFile(frame.ResultPath)
	if err != nil || !bytes.Equal(f.manager.Snapshot().Result, raw) {
		t.Fatal("actual source report was not retained byte exactly")
	}
	if _, err := decodeWorkerReport(raw, frame.ResultToken); err != nil {
		t.Fatal("actual source report failed correlation")
	}
	log, err := os.ReadFile(filepath.Join(filepath.Dir(frame.ResultPath), "process.log"))
	if err != nil || !bytes.Contains(log, []byte("source-pipeline-stdout")) || !bytes.Contains(log, []byte("source-pipeline-stderr")) || !bytes.Contains(log, []byte("child-exited")) {
		t.Fatal("actual stdout, stderr or final timing phase was lost before checked log close")
	}
	receipt := workflowLifecycleReadCurrent(t, f.manager)
	if receipt.Seal == nil || !receipt.Seal.LocalReleasePermitted || receipt.Ack == nil || !receipt.Ack.LocalOwnersReleased {
		t.Fatal("actual owned command/data/output closure was not acknowledged")
	}
}

func TestWorkflowCommandPipelineWrongTokenCannotAcknowledge(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	command, observation, _ := workflowPipelineBind(t, f, "wrong-token")
	job := f.start()
	workflowLifecycleAwait(t, f.manager)
	workflowPipelineObserved(t, *command, *observation, false)
	if !(*command).ProcessState.Success() || !errors.Is(f.manager.TerminalError(job.ID), ErrWorkflowResult) || len(f.manager.Snapshot().Result) != 0 {
		t.Fatal("unrelated report became accepted source pipeline output")
	}
	receipt := workflowLifecycleReadCurrent(t, f.manager)
	if receipt.Seal == nil || receipt.Seal.LocalReleasePermitted || receipt.Ack != nil {
		t.Fatal("uncorrelated actual report was treated as positive local closure evidence")
	}
}

func TestWorkflowCommandPipelineCancellationJoinsActualChildAndOutputs(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	command, observation, _ := workflowPipelineBind(t, f, "cancel")
	job := f.start()
	path := filepath.Join(f.manager.root, job.ID, "result.json")
	logPath := filepath.Join(f.manager.root, job.ID, "process.log")
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
ready:
	for {
		select {
		case <-tick.C:
			// Valid JSON alone can be visible before the child has synced
			// and closed the report. Its fixed stdout marker is emitted only
			// after those operations, then captured by the actual log owner.
			log, err := readWorkflowLifecycleFile(context.Background(), logPath, 64<<10)
			if err != nil || !bytes.Contains(log, []byte("source-pipeline-stdout\n")) {
				continue
			}
			raw, err := readWorkflowLifecycleFile(context.Background(), path, 64<<10)
			if err == nil && json.Valid(raw) {
				break ready
			}
		case <-deadline.C:
			t.Fatal("actual source child did not confirm its closed readiness report through owned output")
		case <-f.manager.done:
			t.Fatal("held source pipeline exited before cancellation")
		}
	}
	f.manager.Cancel()
	workflowLifecycleAwait(t, f.manager)
	workflowPipelineObserved(t, *command, *observation, true)
	var exit *exec.ExitError
	terminal := f.manager.TerminalError(job.ID)
	if (*command).ProcessState.Success() || !errors.As(terminal, &exit) || !errors.Is(terminal, context.Canceled) || len(f.manager.Snapshot().Result) == 0 {
		t.Fatal("actual owned cancellation lost the child exit, context cause or correlated report")
	}
}

type workflowPipelineFailingWriter struct{ err error }

func (w workflowPipelineFailingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWorkflowCommandPipelineLogFailureStopsLiveWorker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")
	frame, err := json.Marshal(map[string]string{"resultPath": path, "resultToken": strings.Repeat("0", 48)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 12*time.Second)
	defer stop()
	cmd, err := workflowPipelineCommand(ctx, frame, "output-failure")
	if err != nil {
		t.Fatal(err)
	}
	logFailure := errors.New("fixture output persistence failure")
	observation, outputClosed, runErr := runWorkflowCommandWithOutput(cmd, configureCommand(cmd), workflowPipelineFailingWriter{err: logFailure})
	if ctx.Err() != nil {
		t.Fatal("log failure left the worker running until the parent deadline")
	}
	if !observation.Accepted || !observation.Bound || !observation.Waited || !observation.OwnerClosed ||
		outputClosed || !errors.Is(runErr, logFailure) || !errors.Is(runErr, ErrWorkflowPersistence) {
		t.Fatalf("incomplete worker failure observations: %+v, outputClosed=%t, error=%v", observation, outputClosed, runErr)
	}
	if cmd.ProcessState.Success() || cmd.ProcessState.ExitCode() == 95 {
		t.Fatal("worker was not terminated by its owner")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("worker did not reach the fixture output boundary", err)
	}
}

type workflowPipelineBlockedWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	writes  atomic.Int32
}

func (writer *workflowPipelineBlockedWriter) Write(data []byte) (int, error) {
	writer.writes.Add(1)
	writer.once.Do(func() { close(writer.entered) })
	<-writer.release
	return len(data), nil
}

func TestWorkflowCommandPipelineCancellationCannotAbandonBlockedOutput(t *testing.T) {
	f := newWorkflowShutdownFixture(t)
	dir := filepath.Join(f.root, "source-output")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("source output fixture directory unavailable")
	}
	frame, err := json.Marshal(map[string]string{"resultPath": filepath.Join(dir, "result.json"), "resultToken": strings.Repeat("0", 48)})
	if err != nil {
		t.Fatal("source output request unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd, err := workflowPipelineCommand(ctx, frame, "complete")
	if err != nil {
		cancel()
		t.Fatal("source output command unavailable")
	}
	writer := &workflowPipelineBlockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(writer.release) }) }
	done := make(chan struct{})
	var observation commandRunObservation
	var outputClosed bool
	var runErr error
	go func() {
		defer close(done)
		observation, outputClosed, runErr = runWorkflowCommandWithOutput(cmd, configureCommand(cmd), writer)
	}()
	t.Cleanup(func() {
		cancel()
		unblock()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			f.preserve = true
			t.Error("source output command did not join; fixture preserved")
		}
	})
	workflowShutdownAwait(t, writer.entered, "source output did not enter its actual destination")
	cancel()
	select {
	case <-done:
		t.Fatal("cancel abandoned an actual blocked destination write")
	case <-time.After(25 * time.Millisecond):
	}
	unblock()
	workflowShutdownAwait(t, done, "released actual output did not join")
	if !observation.Accepted || !observation.Waited || !observation.Bound || !observation.OwnerClosed || !outputClosed || cmd.ProcessState == nil || writer.writes.Load() == 0 {
		t.Fatal("source output completion did not observe every owned pipeline stage")
	}
	// Depending on when the inert child exited, cancellation can retain either
	// its clean actual status or its owned termination status. It cannot erase
	// an output/persistence/owner failure.
	if errors.Is(runErr, ErrWorkflowCleanup) || errors.Is(runErr, ErrWorkflowPersistence) {
		t.Fatal("source output release concealed an actual cleanup or copy failure")
	}
}
