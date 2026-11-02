//go:build darwin && (amd64 || arm64)

package managed

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type darwinCrashBoundary struct {
	name        string
	published   bool
	stage       bool
	files       int
	emptyFile   string
	removedFile string
}

func TestDarwinPairSurvivesTransactionBoundaryTermination(t *testing.T) {
	common := []darwinCrashBoundary{
		{name: "writer-locked"},
		{name: "stage-created", stage: true},
	}
	for index, file := range []string{darwinPolicyFile, darwinAcceptanceFile} {
		for _, step := range []string{"created", "written", "mode", "fsync", "fullsync", "closed"} {
			boundary := darwinCrashBoundary{name: file + "." + step, stage: true, files: index + 1}
			if step == "created" {
				boundary.emptyFile = file
			}
			common = append(common, boundary)
		}
	}
	for _, name := range []string{"candidate-mode", "candidate.fsync", "candidate.fullsync"} {
		common = append(common, darwinCrashBoundary{name: name, stage: true, files: 2})
	}
	for _, name := range []string{"publication-returned", "parent.fsync", "parent.fullsync"} {
		common = append(common, darwinCrashBoundary{name: name, published: true, stage: true, files: 2})
	}
	for _, initial := range []bool{true, false} {
		boundaries := append([]darwinCrashBoundary(nil), common...)
		if !initial {
			for _, file := range []string{darwinPolicyFile, darwinAcceptanceFile} {
				boundaries = append(boundaries, darwinCrashBoundary{name: "cleanup-" + file + "-unlinked", published: true, stage: true, files: -1, removedFile: file})
			}
			for _, name := range []string{"cleanup-removed", "cleanup-parent.fsync", "cleanup-parent.fullsync"} {
				boundaries = append(boundaries, darwinCrashBoundary{name: name, published: true})
			}
		}
		for _, boundary := range boundaries {
			prefix := "initial=false/boundary="
			if initial {
				prefix = "initial=true/boundary="
			}
			t.Run(prefix+boundary.name, func(t *testing.T) { exerciseDarwinCrashBoundary(t, initial, boundary) })
		}
	}
}

func exerciseDarwinCrashBoundary(t *testing.T, initial bool, boundary darwinCrashBoundary) {
	t.Helper()
	prior, next, public, private, now := renewalFixture(t)
	parent, err := os.MkdirTemp(t.TempDir(), "accessweaver-policy-process-")
	if err != nil {
		t.Fatal(err)
	}
	before := machineSnapshot{}
	candidate := prior
	if !initial {
		darwinFixtureInstall(t, parent, prior, now)
		before = darwinStoredPair(t, parent)
		candidate, _, err = installationTransition(before.source, next, nil, false, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	source, acceptance, err := prepareNativeAcceptance(candidate, now)
	if err != nil {
		t.Fatal(err)
	}
	lockInfo := killDarwinTransactionChild(t, darwinProcessFixture{Parent: parent, Initial: initial, Publish: true, Source: source, Acceptance: acceptance, Checkpoint: boundary.name})
	expected := before
	if boundary.published {
		expected = machineSnapshot{source: source, acceptance: acceptance, present: true, acceptancePresent: true}
	}
	parentFD, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := readDarwinSnapshotAt(parentFD, uint32(os.Geteuid()))
	if err := errors.Join(readErr, parentFD.Close()); err != nil {
		t.Fatal(err)
	}
	if actual.present != expected.present || !equalDarwinPair(actual, expected) {
		t.Fatal("crash exposed an incomplete or unexpected active generation")
	}
	if actual.present {
		if _, history, err := decodeMachineSnapshot(actual, now); err != nil || history == nil {
			t.Fatal("active pair lost authenticated history", err)
		}
	}
	stages, err := filepath.Glob(filepath.Join(parent, darwinStagePrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	wantStages := 0
	if boundary.stage && !(initial && boundary.published) {
		wantStages = 1
	}
	if len(stages) != wantStages {
		t.Fatalf("abandoned stage count: got %d want %d", len(stages), wantStages)
	}
	var stageInfo os.FileInfo
	var retained map[string][]byte
	if len(stages) == 1 {
		stageInfo, err = os.Lstat(stages[0])
		if err != nil {
			t.Fatal(err)
		}
		retained = readDarwinAbandonedFixture(t, stages[0])
		if boundary.files >= 0 && len(retained) != boundary.files {
			t.Fatal("unexpected incomplete stage layout", boundary.name, len(retained))
		}
		if boundary.files < 0 {
			if _, exists := retained[boundary.removedFile]; exists || len(retained) > 1 {
				t.Fatal("cleanup boundary did not remove its selected leaf")
			}
		}
		generation := machineSnapshot{source: source, acceptance: acceptance}
		if boundary.published {
			generation = before
		}
		for name, value := range retained {
			want := generation.source
			if name == darwinAcceptanceFile {
				want = generation.acceptance
			}
			if name == boundary.emptyFile {
				want = nil
			}
			if !bytes.Equal(value, want) {
				t.Fatal("unexpected abandoned record bytes", name)
			}
		}
		// A later transaction cannot infer authority over even an empty or partial
		// abandoned directory. Preserve changes and unrelated contents byte for byte.
		for _, name := range []string{darwinPolicyFile, darwinAcceptanceFile} {
			if value, exists := retained[name]; exists {
				retained[name] = append(bytes.Clone(value), ' ')
				if err := os.WriteFile(filepath.Join(stages[0], name), retained[name], 0644); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
		retained["unrelated"] = []byte("preserve this independently changed abandoned stage")
		if err := os.WriteFile(filepath.Join(stages[0], "unrelated"), retained["unrelated"], 0600); err != nil {
			t.Fatal(err)
		}
	}
	retry := darwinFixtureTransaction(t, parent, initial && !boundary.published)
	currentLock, err := retry.lock.Stat()
	if err != nil || !os.SameFile(lockInfo, currentLock) {
		t.Fatal("writer death retained ownership or changed lock identity", err)
	}
	operation, input := changeUpdate, next
	if initial && !boundary.published {
		operation, input = changeInstall, prior
	}
	if !initial && boundary.published {
		payload, err := json.Marshal(Policy{SchemaVersion: 1, Revision: 4, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		input, err = Sign(payload, private, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	result, err := commitInstallation(retry, input, public, operation, func() time.Time { return now })
	if err != nil || !result.Committed {
		t.Fatal("signed transaction could not resume after crash", result, err)
	}
	if _, history, err := decodeMachineSnapshot(darwinStoredPair(t, parent), now); err != nil || history == nil || history.revision != result.Revision {
		t.Fatal("resumed pair is invalid", err)
	}
	if len(stages) == 1 {
		after, err := os.Lstat(stages[0])
		if err != nil || !os.SameFile(stageInfo, after) {
			t.Fatal("restart replaced abandoned directory", err)
		}
		observed := readDarwinAbandonedFixture(t, stages[0])
		if len(observed) != len(retained) {
			t.Fatal("restart changed abandoned layout")
		}
		for name, value := range retained {
			if !bytes.Equal(observed[name], value) {
				t.Fatal("restart changed abandoned bytes", name)
			}
		}
	}
	afterStages, err := filepath.Glob(filepath.Join(parent, darwinStagePrefix+"*"))
	if err != nil || len(afterStages) != wantStages {
		t.Fatal("restart changed abandoned namespace", err)
	}
}

func readDarwinAbandonedFixture(t *testing.T, path string) map[string][]byte {
	t.Helper()
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if len(entries) > 3 {
		t.Fatal("unbounded abandoned fixture")
	}
	values := map[string][]byte{}
	for _, entry := range entries {
		limit := int64(MaxInstallationBytes)
		switch entry.Name() {
		case darwinAcceptanceFile:
			limit = maxAcceptanceBytes
		case darwinPolicyFile:
		case "unrelated":
			limit = 128
		default:
			t.Fatal("unexpected abandoned fixture object", entry.Name())
		}
		value, err := readDarwinValue(dir, entry.Name(), uint32(os.Geteuid()), limit)
		if err != nil {
			t.Fatal(err)
		}
		values[entry.Name()] = value
	}
	return values
}
