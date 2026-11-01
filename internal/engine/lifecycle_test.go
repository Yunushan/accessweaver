package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/profile"
)

// A copy of the test executable acts as an inert foreground engine. It opens no
// sockets and changes no network settings; this tests actual process ownership.
func TestMain(m *testing.M) {
	if os.Getenv("ACCESSWEAVER_FIXTURE") == "1" {
		for _, a := range os.Args {
			if a == "fixture-exit" {
				os.Exit(23)
			}
		}
		cwd, _ := os.Getwd()
		b, _ := json.Marshal(struct {
			Args []string
			Cwd  string
		}{os.Args[1:], cwd})
		// The parent treats record existence as readiness. Publish complete JSON
		// atomically so a scheduled reader cannot observe the newly empty file.
		if err := profile.AtomicWrite(os.Getenv("ACCESSWEAVER_FIXTURE_RECORD"), b); err != nil {
			os.Exit(24)
		}
		fmt.Println("fixture process ready")
		for {
			time.Sleep(time.Hour)
		}
	}
	os.Exit(m.Run())
}

func TestManagedLifecycleLiteralArgumentsAndUnexpectedExit(t *testing.T) {
	root := t.TempDir()
	name := "ciadpi"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(root, name)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.OpenFile(bin, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0700)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	source.Close()
	closeErr := destination.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	record := filepath.Join(root, "record.json")
	t.Setenv("ACCESSWEAVER_FIXTURE", "1")
	t.Setenv("ACCESSWEAVER_FIXTURE_RECORD", record)
	marker := filepath.Join(root, "shell-was-invoked")
	p := profile.New("lifecycle-test", "Lifecycle", "byedpi")
	p.Binary = bin
	p.Args = []string{"literal;$(touch " + marker + ")", "value with spaces"}
	manager := NewManager(filepath.Join(root, "data"))
	t.Cleanup(func() { _ = manager.Stop() })
	if err := manager.Start(p); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(p); err == nil {
		t.Fatal("concurrent engine accepted")
	}
	var data []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err = os.ReadFile(record)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("fixture did not launch: %v; %+v", err, manager.Snapshot())
	}
	var got struct {
		Args []string
		Cwd  string
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := append([]string{"--ip", "127.0.0.1"}, p.Args...)
	if !reflect.DeepEqual(got.Args, want) || got.Cwd != root {
		t.Fatalf("argument/cwd mismatch: %+v", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("shell metacharacters were interpreted")
	}
	if err := manager.Stop(); err != nil {
		t.Fatal(err)
	}
	if s := manager.Snapshot(); s.State != "stopped" || s.PID != 0 || s.LastError != "" {
		t.Fatalf("bad stopped state: %+v", s)
	}
	p.Args = []string{"fixture-exit"}
	if err := manager.Start(p); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && manager.Snapshot().State == "running" {
		time.Sleep(10 * time.Millisecond)
	}
	if s := manager.Snapshot(); s.State != "error" || !strings.Contains(s.LastError, "23") {
		t.Fatalf("unexpected exit not reported: %+v", s)
	}
}
