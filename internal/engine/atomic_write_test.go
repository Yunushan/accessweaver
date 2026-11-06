package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

type atomicWriteGeneratedFixture struct {
	root      string
	profile   profile.Profile
	guard     *managed.Guard
	generated fileidentity.State
	obstacle  fileidentity.State
	preserve  bool
}

func newAtomicWriteGeneratedFixture(t *testing.T) *atomicWriteGeneratedFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-generated-atomic-")
	if err != nil {
		t.Fatal("owned generated-input fixture unavailable")
	}
	identity, err := fileidentity.FromPath(root, false)
	if err != nil || identity.Kind != fileidentity.Directory {
		t.Fatal("owned generated-input fixture identity unavailable; root retained")
	}
	f := &atomicWriteGeneratedFixture{root: root, guard: managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })}
	t.Cleanup(func() {
		if f.preserve {
			t.Error("unconfirmed generated-input fixture retained")
			return
		}
		current, err := fileidentity.FromPath(root, false)
		if err != nil || current.Kind != identity.Kind || current.ID != identity.ID {
			t.Error("changed generated-input fixture retained")
			return
		}
		if os.RemoveAll(root) != nil {
			t.Error("owned generated-input fixture cleanup failed")
		}
	})
	name := "ciadpi"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	f.profile = profile.New("atomic-generated-profile", "PRIVATE_GENERATED_PROFILE", "byedpi")
	f.profile.Binary = filepath.Join(root, name)
	// This is a regular source-owned data file, never an executable fixture.
	// StartTracked's per-instance owner factory below refuses before Start.
	if os.WriteFile(f.profile.Binary, []byte("inert generated-input fixture\n"), 0700) != nil {
		f.preserve = true
		t.Fatal("owned inert adapter fixture write unconfirmed")
	}
	f.profile.Routing.IncludeDomains = []string{"include.example.invalid"}
	f.profile.Routing.ExcludeDomains = []string{"exclude.example.invalid"}
	return f
}

func (f *atomicWriteGeneratedFixture) previewBeforeObstruction(t *testing.T) {
	t.Helper()
	plan, err := NewManagerWithGuard(f.root, f.guard).Preview(f.profile)
	if err != nil || !plan.Ready || len(plan.GeneratedFiles) != 2 {
		t.Fatal("real generated-input preview did not pass prerequisites")
	}
	if _, err := os.Lstat(filepath.Join(f.root, "generated")); !errors.Is(err, os.ErrNotExist) {
		f.preserve = true
		t.Fatal("read-only preview created generated-input evidence")
	}
}

func (f *atomicWriteGeneratedFixture) obstruct(t *testing.T) {
	t.Helper()
	generated := filepath.Join(f.root, "generated")
	obstacle := filepath.Join(generated, f.profile.ID+"-exclude.txt")
	if os.Mkdir(generated, 0700) != nil || os.Mkdir(obstacle, 0700) != nil {
		f.preserve = true
		t.Fatal("owned publication obstruction unavailable")
	}
	var err error
	f.generated, err = fileidentity.FromPath(generated, false)
	if err != nil || f.generated.Kind != fileidentity.Directory {
		f.preserve = true
		t.Fatal("generated directory identity unavailable")
	}
	f.obstacle, err = fileidentity.FromPath(obstacle, false)
	if err != nil || f.obstacle.Kind != fileidentity.Directory {
		f.preserve = true
		t.Fatal("owned obstruction identity unavailable")
	}
}

func (f *atomicWriteGeneratedFixture) read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := fileinput.Read(context.Background(), path, 4096)
	if err != nil {
		f.preserve = true
		t.Fatal("retained generated-input bytes read unconfirmed")
	}
	return data
}

func (f *atomicWriteGeneratedFixture) assertFailureAndEvidence(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, profile.ErrAtomicWriteUncertain) || err.Error() != profile.ErrAtomicWriteUncertain.Error() {
		f.preserve = true
		t.Fatal("generated-input failure lost its fixed atomic category")
	}
	// File methods wrap their failures in PathError. The intended real failure
	// is the later replace operation (LinkError on Unix, native errno on Windows),
	// after the source writer has observed successful Write, Sync and Close.
	var earlierFailure *os.PathError
	if errors.As(err, &earlierFailure) {
		f.preserve = true
		t.Fatal("unexpected source I/O uncertainty preceded the replace refusal")
	}
	generated := filepath.Join(f.root, "generated")
	for _, entry := range []struct {
		path  string
		state fileidentity.State
	}{{generated, f.generated}, {filepath.Join(generated, f.profile.ID+"-exclude.txt"), f.obstacle}} {
		current, failure := fileidentity.FromPath(entry.path, false)
		if failure != nil || current.Kind != entry.state.Kind || current.ID != entry.state.ID {
			f.preserve = true
			t.Fatal("generated-input directory identity changed")
		}
	}
	children, failure := os.ReadDir(filepath.Join(generated, f.profile.ID+"-exclude.txt"))
	if failure != nil || len(children) != 0 {
		f.preserve = true
		t.Fatal("failed publication changed the owned destination directory")
	}
	entries, failure := os.ReadDir(generated)
	if failure != nil || len(entries) != 3 {
		f.preserve = true
		t.Fatal("generated-input evidence count changed")
	}
	stage := ""
	for _, entry := range entries {
		switch {
		case entry.Name() == f.profile.ID+"-include.txt", entry.Name() == f.profile.ID+"-exclude.txt":
		case strings.HasPrefix(entry.Name(), ".accessweaver-") && stage == "":
			stage = filepath.Join(generated, entry.Name())
		default:
			f.preserve = true
			t.Fatal("unexpected generated-input evidence retained")
		}
	}
	if stage == "" {
		f.preserve = true
		t.Fatal("failed publication stage was removed")
	}
	if !bytes.Equal(f.read(t, filepath.Join(generated, f.profile.ID+"-include.txt")), []byte("include.example.invalid\n")) ||
		!bytes.Equal(f.read(t, stage), []byte("exclude.example.invalid\n")) {
		f.preserve = true
		t.Fatal("partial generated-input publication evidence changed")
	}
}

func TestAtomicWriteGeneratedPrepareRetainsEvidence(t *testing.T) {
	f := newAtomicWriteGeneratedFixture(t)
	f.previewBeforeObstruction(t)
	f.obstruct(t)
	// Use Prepare's existing implementation with a source-supplied unmanaged
	// Guard; never query host policy or replace the physical atomic writer.
	binary, args, err := prepareWithGuard(f.profile, f.root, f.guard)
	if binary != "" || args != nil {
		f.preserve = true
		t.Fatal("failed preparation returned launch material")
	}
	f.assertFailureAndEvidence(t, err)
}

func TestAtomicWriteGeneratedStartRetainsEvidenceBeforeOwnerPreparation(t *testing.T) {
	f := newAtomicWriteGeneratedFixture(t)
	f.previewBeforeObstruction(t)
	f.obstruct(t)
	manager := NewManagerWithGuard(f.root, f.guard)
	ownerAttempts := 0
	manager.prepareLifetime = func(*exec.Cmd) (processLifetime, error) {
		ownerAttempts++
		return nil, errors.New("source fixture refuses process ownership")
	}
	run, err := manager.StartTracked(f.profile)
	if run != nil || ownerAttempts != 0 {
		f.preserve = true
		t.Fatal("failed preparation reached process ownership")
	}
	state := manager.Snapshot()
	if state.State != "stopped" || state.PID != 0 || state.LastError != "" || state.LifecyclePending {
		f.preserve = true
		t.Fatal("failed preparation changed process state")
	}
	f.assertFailureAndEvidence(t, err)
}
