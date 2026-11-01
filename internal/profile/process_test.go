package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/filelock"
)

func TestNativeProfileSaveHelper(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_PROFILE_TEST_HELPER") != "1" {
		return
	}
	root := os.Getenv("ACCESSWEAVER_PROFILE_TEST_ROOT")
	id := os.Getenv("ACCESSWEAVER_PROFILE_TEST_ID")
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "reviewed.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "Process " + id
	if err := os.WriteFile(filepath.Join(root, "ready-"+id), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "start")); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("parent did not release process barrier")
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = store.SaveIfUnchanged(p)
	switch {
	case err == nil:
		fmt.Fprintln(os.Stdout, "saved")
	case errors.Is(err, ErrConflict):
		fmt.Fprintln(os.Stdout, "conflict")
	default:
		t.Fatal(err)
	}
}

func TestNativeConcurrentProfileSavesHaveOneWinner(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	p := New("process-shared", "Original", "byedpi")
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	p, err = store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "reviewed.json"), snapshot, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type worker struct {
		cmd    *exec.Cmd
		output bytes.Buffer
		waited bool
	}
	workers := make([]*worker, 6)
	for i := range workers {
		w := &worker{cmd: exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeProfileSaveHelper$")}
		w.cmd.Env = append(os.Environ(), "ACCESSWEAVER_PROFILE_TEST_HELPER=1", "ACCESSWEAVER_PROFILE_TEST_ROOT="+root, "ACCESSWEAVER_PROFILE_TEST_ID="+strconv.Itoa(i))
		w.cmd.Stdout, w.cmd.Stderr = &w.output, &w.output
		if err := w.cmd.Start(); err != nil {
			t.Fatal(err)
		}
		workers[i] = w
		defer func() {
			if !w.waited {
				w.cmd.Process.Kill()
				w.cmd.Wait()
			}
		}()
	}
	for i := range workers {
		for {
			if _, err := os.Stat(filepath.Join(root, "ready-"+strconv.Itoa(i))); err == nil {
				break
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
				t.Fatal("helpers did not reach the save barrier", ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "start"), []byte("start"), 0600); err != nil {
		t.Fatal(err)
	}
	winners := 0
	winner := ""
	for i, w := range workers {
		err := w.cmd.Wait()
		w.waited = true
		if err != nil {
			t.Fatalf("helper %d: %v\n%s", i, err, w.output.String())
		}
		switch {
		case strings.HasPrefix(w.output.String(), "saved\n"):
			winners++
			winner = "Process " + strconv.Itoa(i)
		case strings.HasPrefix(w.output.String(), "conflict\n"):
		default:
			t.Fatalf("unexpected helper result: %s", w.output.String())
		}
	}
	if winners != 1 {
		t.Fatalf("independent-process save winners: %d", winners)
	}
	latest, err := store.Get(p.ID)
	if err != nil || latest.Name != winner || latest.UpdatedAt.Equal(p.UpdatedAt) {
		t.Fatalf("winning revision was not preserved: %+v %v", latest, err)
	}
	other, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.DeleteIfUnchanged(p.ID, p.UpdatedAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("separate store deleted the new revision: %v", err)
	}
}

func TestCanceledStoreMutationDoesNotRunAfterLockRelease(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	p := New("canceled-edit", "Original", "byedpi")
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	original, err := store.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := filelock.TryAcquire(filepath.Join(root, ".profiles.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	edit := original.Copy()
	edit.Name = "Canceled work"
	done := make(chan error, 1)
	go func() { done <- store.SaveIfUnchangedContext(ctx, edit) }()
	select {
	case err := <-done:
		t.Fatalf("writer did not wait for the owner: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation cause lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		owner.Close()
		<-done
		t.Fatal("canceled writer kept waiting for the store")
	}
	owner.Close()
	saved, err := store.Get(p.ID)
	if err != nil || saved.Name != original.Name || !saved.UpdatedAt.Equal(original.UpdatedAt) {
		t.Fatalf("canceled writer changed the saved profile: %+v %v", saved, err)
	}
}
