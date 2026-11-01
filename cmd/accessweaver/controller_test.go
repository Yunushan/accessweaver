package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestControllerOwnershipBlocksCLIImportAndRun(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ACCESSWEAVER_HOME", root)
	owner, err := filelock.TryAcquire(filepath.Join(root, ".controller.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	p := profile.New("controller-test", "Reviewed import", "byedpi")
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "import.json")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"import", source}, {"run", p.ID}} {
		if err := execute(args); err == nil || !strings.Contains(err.Error(), "another AccessWeaver controller") {
			t.Fatalf("%v bypassed controller ownership: %v", args, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "presets-initialized")); !os.IsNotExist(err) {
		t.Fatal("rejected controller changed the profile seed state", err)
	}
	owner.Close()
	if err := execute([]string{"import", source}); err != nil {
		t.Fatal("released controller still blocked imports", err)
	}
	store, err := profile.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(p.ID)
	if err != nil || got.Name != p.Name {
		t.Fatalf("import was lost: %+v %v", got, err)
	}
	if err := execute([]string{"run", "missing-profile"}); err == nil {
		t.Fatal("missing profile unexpectedly launched")
	}
	lock, err := filelock.TryAcquire(filepath.Join(root, ".controller.lock"))
	if err != nil {
		t.Fatal("failed command retained controller ownership", err)
	}
	lock.Close()
}
