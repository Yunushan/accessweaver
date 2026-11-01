package filelock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestExclusiveOwnershipAndIdempotentClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.lock")
	first, err := TryAcquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := TryAcquire(path); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second owner: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := first.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("coordination file was removed", err)
	}
	next, err := TryAcquire(path)
	if err != nil {
		t.Fatal("closed owner retained lock", err)
	}
	defer next.Close()
}

func TestAcquireCancellationAndFilesystemErrors(t *testing.T) {
	root := t.TempDir()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	absent := filepath.Join(root, "must-not-be-created")
	if _, err := Acquire(canceled, absent); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Fatal("canceled acquisition created a file", err)
	}
	path := filepath.Join(root, "busy.lock")
	owner, err := TryAcquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ctx, stop := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer stop()
	if _, err := Acquire(ctx, path); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrBusy) {
		t.Fatalf("contention lost cancellation cause: %v", err)
	}
	if _, err := Acquire(context.Background(), filepath.Join(root, "missing", "owner.lock")); err == nil || errors.Is(err, ErrBusy) {
		t.Fatalf("filesystem failure became contention: %v", err)
	}
	if _, err := TryAcquire(root); err == nil {
		t.Fatal("directory accepted as a lock")
	}
	owner.Close()
	next, err := Acquire(context.Background(), path)
	if err != nil {
		t.Fatal("cancellation retained a handle", err)
	}
	next.Close()
}

func TestSymlinkLockRejected(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires Windows developer mode or privileges")
		}
		t.Fatal(err)
	}
	lock, err := TryAcquire(link)
	if lock != nil {
		lock.Close()
	}
	if err == nil {
		t.Fatal("symlink accepted as coordination file")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("target changed", err)
	}
}

func TestNativeLockHelper(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_FILELOCK_TEST_HELPER") != "1" {
		return
	}
	lock, err := TryAcquire(os.Getenv("ACCESSWEAVER_FILELOCK_TEST_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	fmt.Fprintln(os.Stdout, "locked")
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}

func TestNativeProcessOwnershipAndForcedExit(t *testing.T) {
	for _, forced := range []bool{false, true} {
		name := "normal-exit"
		if forced {
			name = "forced-exit"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "process.lock")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeLockHelper$")
			cmd.Env = append(os.Environ(), "ACCESSWEAVER_FILELOCK_TEST_HELPER=1", "ACCESSWEAVER_FILELOCK_TEST_PATH="+path)
			cmd.Stderr = os.Stderr
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				stdin.Close()
				if !waited {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			ready := make(chan error, 1)
			go func() {
				line, err := bufio.NewReader(stdout).ReadString('\n')
				if err == nil && line != "locked\n" {
					err = fmt.Errorf("unexpected helper output %q", line)
				}
				ready <- err
			}()
			select {
			case err := <-ready:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("helper did not acquire the lock", ctx.Err())
			}
			if lock, err := TryAcquire(path); !errors.Is(err, ErrBusy) {
				if lock != nil {
					lock.Close()
				}
				t.Fatalf("another process did not hold exclusive ownership: %v", err)
			}
			if forced {
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			} else {
				stdin.Close()
			}
			err = cmd.Wait()
			waited = true
			if !forced && err != nil {
				t.Fatal("normal helper exit", err)
			}
			if forced && err == nil {
				t.Fatal("forced helper unexpectedly exited successfully")
			}
			lock, err := TryAcquire(path)
			if err != nil {
				t.Fatal("terminated process retained ownership", err)
			}
			lock.Close()
			if _, err := os.Stat(path); err != nil {
				t.Fatal("lock path disappeared", err)
			}
		})
	}
}
