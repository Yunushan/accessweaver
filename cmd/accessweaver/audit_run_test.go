package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
)

func TestRecordedEngineExactOptionsRefuseBeforeStoreAccess(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-not-be-created")
	t.Setenv("ACCESSWEAVER_HOME", root)
	good := []string{"run", "--directory", "PRIVATE_DIRECTORY", "--from", "PRIVATE_GENESIS", "--to", "PRIVATE_HEAD", "--profile", "PRIVATE_PROFILE", "--consent", "metadata-only"}
	duplicate := append([]string(nil), good...)
	duplicate[5] = "--from"
	unknown := append([]string(nil), good...)
	unknown[7] = "--unknown"
	consent := append([]string(nil), good...)
	consent[10] = "PRIVATE_CONSENT"
	empty := append([]string(nil), good...)
	empty[8] = ""
	for _, args := range [][]string{nil, {"run"}, good[:9], duplicate, unknown, consent, empty, append(append([]string(nil), good...), "extra")} {
		if err := auditRunCommand(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid options reached admission or disclosed input", err)
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("invalid options created controller or profile storage", err)
	}
	if _, err := recordedRunPaths(good); err != nil {
		t.Fatal("valid named options refused", err)
	}
}

type recordedEngineCloseFunc func() error

func (f recordedEngineCloseFunc) Close() error { return f() }

func TestRecordedEngineCloseKeepsControllerUntilJournalReturns(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	controllerClosed := make(chan struct{})
	finished := make(chan error, 1)
	journalCloses, controllerCloses := 0, 0
	journal := recordedEngineCloseFunc(func() error {
		journalCloses++
		close(entered)
		<-release
		return errors.New("PRIVATE_JOURNAL_CLOSE")
	})
	controller := recordedEngineCloseFunc(func() error {
		controllerCloses++
		close(controllerClosed)
		return errors.New("PRIVATE_CONTROLLER_CLOSE")
	})
	go func() { finished <- closeRecordedEngineScope(journal, controller) }()
	<-entered
	select {
	case <-controllerClosed:
		t.Fatal("controller was released while journal close remained active")
	default:
	}
	unblock()
	select {
	case err := <-finished:
		if !errors.Is(err, audit.ErrRecordedUncertain) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("cleanup uncertainty was lost or disclosed private errors", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after journal close returned")
	}
	if journalCloses != 1 || controllerCloses != 1 {
		t.Fatal("owning cleanup was skipped or retried", journalCloses, controllerCloses)
	}
	select {
	case <-controllerClosed:
	default:
		t.Fatal("failed journal close prevented controller cleanup attempt")
	}
	if err := closeRecordedEngineScope(nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRecordedEngineClosePreservesSuccessfulOwnershipOrder(t *testing.T) {
	order := ""
	var journal io.Closer = recordedEngineCloseFunc(func() error { order += "journal;"; return nil })
	var controller io.Closer = recordedEngineCloseFunc(func() error { order += "controller;"; return nil })
	if err := closeRecordedEngineScope(journal, controller); err != nil || order != "journal;controller;" {
		t.Fatal("successful cleanup order changed", order, err)
	}
}
