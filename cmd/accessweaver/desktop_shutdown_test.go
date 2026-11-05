package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type desktopShutdownFixture struct {
	done, pending chan struct{}
	final         error
	waits         int
}

func (s *desktopShutdownFixture) Done() <-chan struct{}            { return s.done }
func (s *desktopShutdownFixture) ShutdownPending() <-chan struct{} { return s.pending }
func (s *desktopShutdownFixture) Wait() error                      { s.waits++; return s.final }

func TestDesktopShutdownPendingRetainsScopeUntilActualCompletion(t *testing.T) {
	actual := errors.New("PRIVATE_ENGINE_LIFECYCLE")
	server := &desktopShutdownFixture{done: make(chan struct{}), pending: make(chan struct{}), final: actual}
	feedback := foregroundFeedbackReceipt{written: make(chan string, 1)}
	finished, returned := make(chan error, 1), make(chan struct{})
	cleanupForegroundFixture(t, server.done, returned)
	go func() { defer close(returned); finished <- waitDesktopShutdown(server, feedback) }()
	close(server.pending)
	select {
	case text := <-feedback.written:
		if bytes.Contains([]byte(text), []byte("PRIVATE")) || !bytes.Contains([]byte(text), []byte("keep this command active")) {
			t.Error("shutdown feedback missing or private", text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending desktop shutdown was silent")
	}
	select {
	case err := <-finished:
		t.Fatal("pending desktop shutdown abandoned its scope", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(server.done)
	select {
	case err := <-finished:
		if !errors.Is(err, actual) || server.waits != 1 {
			t.Fatal("final engine lifecycle result lost", err, server.waits)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual desktop shutdown not observed")
	}
}

func TestDesktopShutdownPrefersCompletionOverPendingFeedback(t *testing.T) {
	server := &desktopShutdownFixture{done: make(chan struct{}), pending: make(chan struct{})}
	close(server.pending)
	close(server.done)
	feedback := &bytes.Buffer{}
	if err := waitDesktopShutdown(server, feedback); err != nil || feedback.Len() != 0 || server.waits != 1 {
		t.Fatal("terminal shutdown produced stale warning or lost result", err, feedback.String(), server.waits)
	}
	if err := waitDesktopShutdown(&desktopShutdownFixture{}, io.Discard); err == nil {
		t.Fatal("missing desktop handle became completed shutdown")
	}
}

type failedDesktopShutdownNotice struct {
	entered chan struct{}
	short   bool
}

func (w failedDesktopShutdownNotice) Write(data []byte) (int, error) {
	close(w.entered)
	if w.short {
		return len(data) - 1, nil
	}
	return 0, errors.New("PRIVATE_OUTPUT_FAILURE")
}

func TestDesktopShutdownFeedbackFailureStillDrainsOwnedWork(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "write-error", true: "short-write"}[short], func(t *testing.T) {
			server := &desktopShutdownFixture{done: make(chan struct{}), pending: make(chan struct{})}
			feedback := failedDesktopShutdownNotice{entered: make(chan struct{}), short: short}
			finished, returned := make(chan error, 1), make(chan struct{})
			cleanupForegroundFixture(t, server.done, returned)
			close(server.pending)
			go func() { defer close(returned); finished <- waitDesktopShutdown(server, feedback) }()
			select {
			case <-feedback.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown feedback not attempted")
			}
			select {
			case err := <-finished:
				t.Fatal("failed feedback abandoned owned work", err)
			case <-time.After(25 * time.Millisecond):
			}
			close(server.done)
			select {
			case err := <-finished:
				if !errors.Is(err, errDesktopShutdownOutput) || strings.Contains(err.Error(), "PRIVATE") || server.waits != 1 {
					t.Fatal("output failure lost or disclosed before completed drain", err, server.waits)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown feedback failure did not observe final work")
			}
		})
	}
}
