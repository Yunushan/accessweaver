//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// Only the copied, source-built inert test executable enters these modes. The
// real application has neither this branch nor its private PID observation.
func init() {
	if os.Getenv("ACCESSWEAVER_RECORDED_ENGINE_FIXTURE") != "1" {
		return
	}
	for _, argument := range os.Args[1:] {
		if argument != "recorded-engine-exit-zero" && argument != "recorded-engine-exit-fail" && argument != "recorded-engine-wait" {
			continue
		}
		if err := os.WriteFile(os.Getenv("ACCESSWEAVER_RECORDED_ENGINE_PID"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(24)
		}
		switch argument {
		case "recorded-engine-exit-zero":
			os.Exit(0)
		case "recorded-engine-exit-fail":
			os.Exit(23)
		default:
			for {
				time.Sleep(time.Hour)
			}
		}
	}
}

type recordedEngineNativeFixture struct {
	base, directory, from, to, input, profiles, binary, pid string
	start                                                   audit.Checkpoint
	profile                                                 profile.Profile
	key                                                     []byte
}

func newRecordedEngineNativeFixture(t *testing.T, mode string) recordedEngineNativeFixture {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("ordinary-user source fixture; not an installed or elevated product test")
	}
	base, directory, from, to, start := recordedExportNativeFixture(t)
	f := recordedEngineNativeFixture{
		base: base, directory: directory, from: from, to: to, start: start,
		input:    filepath.Join(base, "PRIVATE_ENGINE_PROFILE.json"),
		profiles: filepath.Join(base, "no-seeded-profile-inventory"),
		binary:   filepath.Join(base, "ciadpi"), pid: filepath.Join(base, "owned-child.pid"),
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.binary, data, 0700); err != nil {
		t.Fatal(err)
	}
	f.profile = profile.New("recorded-engine", "PRIVATE_ENGINE_DISPLAY_NAME", "byedpi")
	f.profile.Binary = f.binary
	f.profile.Args = []string{mode, "PRIVATE_ENGINE_ARGUMENT"}
	writeRecordedEngineProfile(t, f.input, f.profile)
	f.key, err = os.ReadFile(filepath.Join(directory, ".actor-key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACCESSWEAVER_HOME", f.profiles)
	t.Setenv("ACCESSWEAVER_RECORDED_ENGINE_FIXTURE", "1")
	t.Setenv("ACCESSWEAVER_RECORDED_ENGINE_PID", f.pid)
	return f
}

func writeRecordedEngineProfile(t *testing.T, path string, p profile.Profile) {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func recordedEngineNativeArgs(f recordedEngineNativeFixture) []string {
	return []string{"run", "--directory", f.directory, "--from", f.from, "--to", f.to, "--profile", f.input, "--consent", "metadata-only"}
}

func assertRecordedEngineNoInventory(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "profiles"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("recorded launch wrote or seeded the profile inventory")
	}
	if _, err := os.Stat(filepath.Join(root, "presets-initialized")); !os.IsNotExist(err) {
		t.Fatal("recorded launch seeded built-in profiles")
	}
}

// Inspect the observed source-test bytes without adopting a disk-derived head
// as an independently retained checkpoint or opening another writer with it.
func readRecordedEngineNativeEvents(t *testing.T, directory string, start audit.Checkpoint) ([]audit.Event, audit.Checkpoint, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, "events.journal"))
	if err != nil {
		t.Fatal(err)
	}
	rows := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(rows) < 1 {
		t.Fatal("missing source-test journal genesis")
	}
	genesis, err := audit.DecodeCheckpoint(append(bytes.Clone(rows[0]), '\n'))
	if err != nil || genesis != start {
		t.Fatal("source-test genesis changed", err)
	}
	end := start
	events := make([]audit.Event, 0, len(rows)-1)
	for _, row := range rows[1:] {
		var record struct {
			Sequence uint64      `json:"sequence"`
			SHA256   string      `json:"sha256"`
			Event    audit.Event `json:"event"`
		}
		if err := json.Unmarshal(row, &record); err != nil {
			t.Fatal(err)
		}
		events = append(events, record.Event)
		end.Sequence, end.SHA256 = record.Sequence, record.SHA256
	}
	segment := []byte{}
	if len(rows) > 1 {
		segment = append(bytes.Join(rows[1:], []byte{'\n'}), '\n')
	}
	verified, err := audit.VerifySegment(context.Background(), bytes.NewReader(segment), start, end)
	if err != nil || verified.Records != len(events) {
		t.Fatal("source-test metadata segment does not verify", err)
	}
	return events, end, raw
}

func assertRecordedEngineNativeLifecycle(t *testing.T, events []audit.Event, terminal string) {
	t.Helper()
	if len(events) != 3 {
		t.Fatal("missing intent, acceptance or actual terminal observation", len(events))
	}
	operation := events[0].OperationID
	for i, outcome := range []string{"intent", "accepted", terminal} {
		if events[i].Action != "engine.start" || events[i].Outcome != outcome || events[i].OperationID != operation || len(operation) != 32 {
			t.Fatal("actual foreground lifecycle order or identity differs", i)
		}
	}
}

func TestRecordedEngineRealCLIJournalActualExitAndNoProfileSeeding(t *testing.T) {
	for _, test := range []struct {
		mode, terminal string
		fails          bool
	}{
		{"recorded-engine-exit-zero", "completed", false},
		{"recorded-engine-exit-fail", "failed", true},
	} {
		t.Run(test.terminal, func(t *testing.T) {
			f := newRecordedEngineNativeFixture(t, test.mode)
			inputBefore, err := os.ReadFile(f.input)
			if err != nil {
				t.Fatal(err)
			}
			observations, notice, commandErr := captureRecordedExportCLI(t, recordedEngineNativeArgs(f))
			if (commandErr != nil) != test.fails {
				t.Fatal("real recorded command misclassified actual process exit", commandErr)
			}
			if _, err := os.Stat(f.pid); err != nil {
				t.Fatal("recorded command did not launch the source-built inert process", err)
			}
			checkpoints := decodeCheckpointObservations(t, observations)
			if len(checkpoints) != 3 || checkpoints[0].Sequence != 1 || checkpoints[1].Sequence != 2 || checkpoints[2].Sequence != 3 {
				t.Fatal("real command omitted canonical intent/accepted/terminal checkpoints")
			}
			events, end, raw := readRecordedEngineNativeEvents(t, f.directory, f.start)
			assertRecordedEngineNativeLifecycle(t, events, test.terminal)
			if end != checkpoints[2] {
				t.Fatal("observed terminal checkpoint does not name the actual local journal")
			}
			if len(notice) == 0 || bytes.Contains(notice, []byte("PRIVATE_")) || bytes.Contains(observations, []byte("PRIVATE_")) || bytes.Contains(raw, []byte("PRIVATE_")) || bytes.Contains(raw, f.key) {
				t.Fatal("private profile, actor key or process data escaped metadata observations")
			}
			if now, err := os.ReadFile(f.input); err != nil || !bytes.Equal(now, inputBefore) {
				t.Fatal("launch imported or changed the reviewed profile input", err)
			}
			if now, err := os.ReadFile(filepath.Join(f.directory, ".actor-key")); err != nil || !bytes.Equal(now, f.key) {
				t.Fatal("launch replaced the enrolled actor key", err)
			}
			assertRecordedEngineNoInventory(t, f.profiles)
			// Opening against the independently observed head also proves the command
			// released its exclusive native writer after terminal publication.
			journal, err := audit.OpenLocalJournal(context.Background(), f.directory, f.start, checkpoints[2])
			if err != nil {
				t.Fatal("real command retained its journal writer", err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			lock, err := filelock.TryAcquire(filepath.Join(f.profiles, ".controller.lock"))
			if err != nil {
				t.Fatal("real command retained controller ownership", err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecordedEngineNativeStaleHeadAndKeyLossNeverDispatch(t *testing.T) {
	t.Run("stale-head", func(t *testing.T) {
		f := newRecordedEngineNativeFixture(t, "recorded-engine-exit-zero")
		observed, _, err := captureRecordedExportCLI(t, recordedEngineNativeArgs(f))
		if err != nil {
			t.Fatal(err)
		}
		if len(decodeCheckpointObservations(t, observed)) != 3 {
			t.Fatal("missing initial completed run")
		}
		if err := os.Remove(f.pid); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(filepath.Join(f.directory, "events.journal"))
		if err != nil {
			t.Fatal(err)
		}
		observed, _, err = captureRecordedExportCLI(t, recordedEngineNativeArgs(f))
		if err == nil || len(observed) != 0 {
			t.Fatal("stale head admitted another engine lifecycle")
		}
		if _, err := os.Stat(f.pid); !os.IsNotExist(err) {
			t.Fatal("stale head launched an unrecorded process")
		}
		if now, err := os.ReadFile(filepath.Join(f.directory, "events.journal")); err != nil || !bytes.Equal(now, before) {
			t.Fatal("stale-head refusal changed the retained journal", err)
		}
		assertRecordedEngineNoInventory(t, f.profiles)
	})
	t.Run("missing-actor-key", func(t *testing.T) {
		f := newRecordedEngineNativeFixture(t, "recorded-engine-exit-zero")
		before, err := os.ReadFile(filepath.Join(f.directory, "events.journal"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(f.directory, ".actor-key")); err != nil {
			t.Fatal(err)
		}
		observed, _, err := captureRecordedExportCLI(t, recordedEngineNativeArgs(f))
		if err == nil || len(observed) != 0 {
			t.Fatal("missing actor key admitted an engine lifecycle")
		}
		if _, err := os.Stat(f.pid); !os.IsNotExist(err) {
			t.Fatal("missing actor key launched an unrecorded process")
		}
		if now, err := os.ReadFile(filepath.Join(f.directory, "events.journal")); err != nil || !bytes.Equal(now, before) {
			t.Fatal("missing-key refusal changed journal bytes", err)
		}
		if _, err := os.Stat(f.profiles); !os.IsNotExist(err) {
			t.Fatal("missing-key admission created profile storage")
		}
	})
}

func TestRecordedEngineNativeControllerAndOutputAliasesRefuseBeforeIntent(t *testing.T) {
	t.Run("controller-busy", func(t *testing.T) {
		f := newRecordedEngineNativeFixture(t, "recorded-engine-exit-zero")
		if _, err := profile.NewStore(f.profiles); err != nil {
			t.Fatal(err)
		}
		lock, err := filelock.TryAcquire(filepath.Join(f.profiles, ".controller.lock"))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		var observations, notice bytes.Buffer
		if err := auditRunCommand(recordedEngineNativeArgs(f), &observations, &notice); err == nil {
			t.Fatal("busy controller admitted a recorded launch")
		}
		events, _, _ := readRecordedEngineNativeEvents(t, f.directory, f.start)
		if len(events) != 0 || observations.Len() != 0 {
			t.Fatal("controller refusal recorded or dispatched an operation")
		}
		if _, err := os.Stat(f.pid); !os.IsNotExist(err) {
			t.Fatal("busy controller launched a process")
		}
	})
	for _, target := range []string{"from", "to", "profile", "journal", "actor-key", "executable", "configuration", "generated", "controller-lock", "profile-lock"} {
		for _, channel := range []string{"observations", "notice"} {
			t.Run(target+"/"+channel, func(t *testing.T) {
				f := newRecordedEngineNativeFixture(t, "recorded-engine-exit-zero")
				path := recordedEngineNativeAliasPath(t, &f, target)
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				out, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer out.Close()
				var other bytes.Buffer
				var observed, notice io.Writer = out, &other
				if channel == "notice" {
					observed, notice = &other, out
				}
				if err := auditRunCommand(recordedEngineNativeArgs(f), observed, notice); !errors.Is(err, errAuditRunOutput) {
					t.Fatal("known input was not refused by output-alias validation", err)
				}
				if now, err := os.ReadFile(path); err != nil || !bytes.Equal(now, before) {
					t.Fatal("output-alias refusal changed protected input", err)
				}
				events, _, _ := readRecordedEngineNativeEvents(t, f.directory, f.start)
				if len(events) != 0 {
					t.Fatal("output-alias refusal appended an intent")
				}
				if _, err := os.Stat(f.pid); !os.IsNotExist(err) {
					t.Fatal("output alias dispatched the engine")
				}
			})
		}
	}
	t.Run("shared-output-file", func(t *testing.T) {
		f := newRecordedEngineNativeFixture(t, "recorded-engine-exit-zero")
		out, err := os.Create(filepath.Join(f.base, "shared-output"))
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		if err := auditRunCommand(recordedEngineNativeArgs(f), out, out); err == nil {
			t.Fatal("one file accepted mixed canonical checkpoints and notice data")
		}
		events, _, _ := readRecordedEngineNativeEvents(t, f.directory, f.start)
		if len(events) != 0 {
			t.Fatal("shared output file admitted an operation")
		}
	})
}

var _ = errors.Is
var _ = strings.Contains

func recordedEngineNativeAliasPath(t *testing.T, f *recordedEngineNativeFixture, target string) string {
	t.Helper()
	paths := map[string]string{"from": f.from, "to": f.to, "profile": f.input, "journal": filepath.Join(f.directory, "events.journal"), "actor-key": filepath.Join(f.directory, ".actor-key"), "executable": f.binary}
	if path, ok := paths[target]; ok {
		return path
	}
	switch target {
	case "configuration":
		binary := filepath.Join(f.base, "sing-box")
		if err := os.Rename(f.binary, binary); err != nil {
			t.Fatal(err)
		}
		f.binary = binary
		f.profile.Engine = "sing-box"
		f.profile.Binary = binary
		f.profile.ConfigPath = filepath.Join(f.base, "PRIVATE_ENGINE_CONFIG.json")
		if err := os.WriteFile(f.profile.ConfigPath, []byte("{}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		writeRecordedEngineProfile(t, f.input, f.profile)
		return f.profile.ConfigPath
	case "generated":
		f.profile.Routing.IncludeDomains = []string{"example.invalid"}
		writeRecordedEngineProfile(t, f.input, f.profile)
		directory := filepath.Join(f.profiles, "generated")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, f.profile.ID+"-include.txt")
		if err := os.WriteFile(path, []byte("PRIVATE_EXISTING_HOST_INPUT\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	case "controller-lock", "profile-lock":
		if _, err := profile.NewStore(f.profiles); err != nil {
			t.Fatal(err)
		}
		name := ".controller.lock"
		if target == "profile-lock" {
			name = ".profiles.lock"
		}
		path := filepath.Join(f.profiles, name)
		lock, err := filelock.TryAcquire(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	default:
		t.Fatal("unknown source-test alias target")
		return ""
	}
}

func TestRecordedEngineNativeInvalidProfileRefusesWithoutPrivateErrorOrMutation(t *testing.T) {
	f := newRecordedEngineNativeFixture(t, "recorded-engine-exit-zero")
	before, err := os.ReadFile(filepath.Join(f.directory, "events.journal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.input, []byte(`{"id":"PRIVATE_INVALID_PROFILE","raw":"PRIVATE_TOKEN"`), 0600); err != nil {
		t.Fatal(err)
	}
	var observations, notice bytes.Buffer
	err = auditRunCommand(recordedEngineNativeArgs(f), &observations, &notice)
	if !errors.Is(err, errAuditRunProfile) || strings.Contains(err.Error(), "PRIVATE") || observations.Len() != 0 || notice.Len() != 0 {
		t.Fatal("invalid profile was not safely refused before recording", err)
	}
	if now, err := os.ReadFile(filepath.Join(f.directory, "events.journal")); err != nil || !bytes.Equal(now, before) {
		t.Fatal("invalid profile changed retained journal", err)
	}
	if _, err := os.Stat(f.pid); !os.IsNotExist(err) {
		t.Fatal("invalid profile dispatched a process")
	}
	if _, err := os.Stat(f.profiles); !os.IsNotExist(err) {
		t.Fatal("invalid profile created profile inventory")
	}
}
