package workflow

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/logfile"
)

type startupWriterFunc func([]byte) (int, error)

func (f startupWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestStartupLogPreservesChildBytesAndIgnoresEmptyWrites(t *testing.T) {
	var data bytes.Buffer
	log := &startupLog{writer: &data, started: time.Now()}
	if n, err := log.Write(nil); n != 0 || err != nil || data.Len() != 0 {
		t.Fatal("empty write invented child output")
	}
	for _, text := range []string{"first\n", "second\n"} {
		if n, err := log.Write([]byte(text)); n != len(text) || err != nil {
			t.Fatal("child write changed", n, err)
		}
	}
	line, child, ok := strings.Cut(data.String(), "\n")
	if !ok || !regexp.MustCompile(`^Workflow timing ms: first-output [0-9]+$`).MatchString(line) || child != "first\nsecond\n" {
		t.Fatal("startup timing changed child bytes")
	}
}

func TestStartupLogFailurePreventsFalseCaptureSuccess(t *testing.T) {
	for _, short := range []bool{false, true} {
		sentinel := errors.New("injected log failure")
		if short {
			sentinel = io.ErrShortWrite
		}
		calls := 0
		writer := startupWriterFunc(func(p []byte) (int, error) {
			calls++
			if short {
				return len(p) - 1, nil
			}
			return 0, sentinel
		})
		log := &startupLog{writer: writer, started: time.Now()}
		for i := 0; i < 2; i++ {
			if n, err := log.Write([]byte("child data")); n != 0 || !errors.Is(err, sentinel) {
				t.Fatal("log failure became successful capture", n, err)
			}
		}
		if calls != 1 {
			t.Fatal("failed prefix was retried or child data was forwarded")
		}
	}
}

func TestStartupLogConcurrentStreamsEmitOneTimingMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "process.log")
	writer, err := logfile.Open(path, 64<<10, 1)
	if err != nil {
		t.Fatal(err)
	}
	log := &startupLog{writer: writer, started: time.Now()}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n, err := log.Write([]byte("child-stream\n")); n != 13 || err != nil {
				t.Error("stream write failed", n, err)
			}
		}()
	}
	wg.Wait()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "Workflow timing ms: first-output ") != 1 || strings.Count(string(data), "child-stream\n") != 8 {
		t.Fatal("concurrent capture lost or duplicated output")
	}
}

func TestStartupLogRetainsDataWriteErrorAndShortWrite(t *testing.T) {
	for _, short := range []bool{false, true} {
		sentinel := errors.New("PRIVATE_CHILD_OUTPUT_FAILURE")
		if short {
			sentinel = io.ErrShortWrite
		}
		calls := 0
		log := &startupLog{writer: startupWriterFunc(func(p []byte) (int, error) {
			calls++
			if calls == 1 {
				return len(p), nil
			} // First-output timing succeeds.
			if short {
				return len(p) - 1, nil
			}
			return 0, sentinel
		}), started: time.Now()}
		if _, err := log.Write([]byte("child-output")); !errors.Is(err, sentinel) {
			t.Fatal("child output failure was erased")
		}
		if !errors.Is(log.failure(), sentinel) {
			t.Fatal("child output uncertainty was not retained independently")
		}
	}
}
