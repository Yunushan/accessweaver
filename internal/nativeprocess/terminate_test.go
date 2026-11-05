package nativeprocess

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Only tests invoke this closed source-built subprocess protocol. There is no
// runtime environment switch or substitute trusted Windows utility path.
func TestNativeProcessHelper(t *testing.T) {
	marker := -1
	for i, arg := range os.Args {
		if arg == "--" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	args := os.Args[marker+1:]
	if len(args) == 0 {
		os.Exit(2)
	}
	switch args[0] {
	case "sleep":
		time.Sleep(45 * time.Second)
	case "controlled":
		if _, err := os.Stdout.Write([]byte{'r'}); err != nil {
			os.Exit(2)
		}
		input := make(chan byte, 4)
		go func() {
			defer close(input)
			var value [1]byte
			for {
				if _, err := io.ReadFull(os.Stdin, value[:]); err != nil {
					return
				}
				input <- value[0]
			}
		}()
		timer := time.NewTimer(45 * time.Second)
		defer timer.Stop()
		for {
			select {
			case value, ok := <-input:
				if !ok {
					os.Exit(2)
				}
				if value == 'q' {
					os.Exit(0)
				}
				if value != 'p' {
					os.Exit(2)
				}
				if _, err := os.Stdout.Write([]byte{'p'}); err != nil {
					os.Exit(2)
				}
			case <-timer.C:
				os.Exit(2)
			}
		}
	case "hang":
		if len(args) != 2 || os.WriteFile(args[1], []byte("started"), 0600) != nil {
			os.Exit(2)
		}
		time.Sleep(45 * time.Second)
	case "fail":
		os.Exit(7)
	default:
		os.Exit(2)
	}
}

type sourceProcessOutput struct {
	mu      sync.Mutex
	events  chan byte
	bytes   int
	invalid bool
}

func (w *sourceProcessOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bytes += len(data)
	if w.bytes > 64 {
		w.invalid = true
		return len(data), nil
	}
	for _, value := range data {
		if value != 'r' && value != 'p' {
			w.invalid = true
		}
		select {
		case w.events <- value:
		default:
			w.invalid = true
		}
	}
	return len(data), nil
}

type sourceSleepingProcess struct {
	t           *testing.T
	cmd         *exec.Cmd
	input       io.WriteCloser
	output      *sourceProcessOutput
	waitStarted bool
	done        chan struct{}
	waitErr     error
}

func sleepingProcess(t *testing.T) *sourceSleepingProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNativeProcessHelper$", "--", "controlled")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal("source process control pipe unavailable")
	}
	output := &sourceProcessOutput{events: make(chan byte, 8)}
	cmd.Stdout, cmd.Stderr = output, io.Discard
	if cmd.Start() != nil {
		_ = input.Close()
		t.Fatal("source process launch failed")
	}
	process := &sourceSleepingProcess{t: t, cmd: cmd, input: input, output: output}
	t.Cleanup(func() {
		// All allowed signals precede the sole Wait. A completed/reaping child is
		// never signaled again, including on assertion-failure cleanup paths.
		if !process.waitStarted {
			_ = cmd.Process.Kill()
			process.beginWait()
		}
		select {
		case <-process.done:
		case <-time.After(8 * time.Second):
			t.Error("owned source process completion unconfirmed")
		}
		if err := input.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error("source process control close failed")
		}
	})
	process.read('r')
	return process
}
func (p *sourceSleepingProcess) read(want byte) {
	p.t.Helper()
	select {
	case value := <-p.output.events:
		if value != want {
			p.t.Fatal("source process protocol mismatch")
		}
	case <-time.After(8 * time.Second):
		p.t.Fatal("source process protocol timed out")
	}
}
func (p *sourceSleepingProcess) beginWait() {
	p.t.Helper()
	if p.waitStarted {
		p.t.Fatal("source process Wait repeated")
	}
	p.waitStarted = true
	p.done = make(chan struct{})
	go func() { defer close(p.done); p.waitErr = p.cmd.Wait() }()
}
func (p *sourceSleepingProcess) wait() {
	p.t.Helper()
	if !p.waitStarted {
		p.beginWait()
	}
	select {
	case <-p.done:
	case <-time.After(8 * time.Second):
		p.t.Fatal("owned source process did not exit")
	}
}
func (p *sourceSleepingProcess) ping() {
	p.t.Helper()
	if n, err := p.input.Write([]byte{'p'}); err != nil || n != 1 {
		p.t.Fatal("distinct source process control failed")
	}
	p.read('p')
}

func TestFailedTerminationStillKillsOwnedParent(t *testing.T) {
	for _, mode := range []string{"missing", "fail", "hang"} {
		t.Run(mode, func(t *testing.T) {
			child, unrelated := sleepingProcess(t), sleepingProcess(t)
			ready := filepath.Join(t.TempDir(), "helper-started")
			spec := terminationCommand{executable: os.Args[0], args: []string{"-test.run=^TestNativeProcessHelper$", "--", mode}}
			if mode == "missing" {
				spec.executable = filepath.Join(t.TempDir(), "missing-helper")
			}
			if mode == "hang" {
				spec.args = append(spec.args, ready)
			}
			started := time.Now()
			err := terminateWithCommand(child.cmd.Process, spec, 2*time.Second)
			if err == nil {
				t.Fatal("unconfirmed tree cleanup reported success")
			}
			if time.Since(started) > 8*time.Second {
				t.Fatal("termination helper exceeded deadline and wait allowance")
			}
			switch mode {
			case "missing":
				if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, exec.ErrNotFound) {
					t.Fatal("missing helper cause was lost")
				}
			case "fail":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 {
					t.Fatal("helper failure exit was lost")
				}
			case "hang":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("hung helper deadline was lost")
				}
				if data, e := os.ReadFile(ready); e != nil || string(data) != "started" {
					t.Fatal("hung helper was not confirmed live")
				}
			}
			child.wait()
			if child.waitErr == nil {
				t.Fatal("fallback did not terminate the exact owned parent")
			}
			unrelated.ping() // A real responsive peer, not an unstarted Wait channel.
		})
	}
}
func TestNilProcessDoesNotLaunchTerminator(t *testing.T) {
	if err := terminateWithCommand(nil, terminationCommand{executable: "missing-helper"}, 0); err != nil {
		t.Fatal("nil process launched termination helper")
	}
}
