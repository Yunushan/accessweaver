//go:build windows

package workflow

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/nativepath"
)

// Real OS discovery is read-only: no networking, installation, DNS or service changes.
func TestNativeDiscoveryIgnoresUntrustedEnvironment(t *testing.T) {
	expected, err := nativepath.ProgramData()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fakeRoot := filepath.Join(root, "must-not-create")
	modules := filepath.Join(root, "modules")
	module := filepath.Join(modules, "ScheduledTasks")
	if err := os.MkdirAll(module, 0700); err != nil {
		t.Fatal(err)
	}
	source := `function Get-ScheduledTask { [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'module-loaded.txt'),'unexpected');throw 'UNTRUSTED_MODULE' };Export-ModuleMember -Function Get-ScheduledTask`
	if err := os.WriteFile(filepath.Join(module, "ScheduledTasks.psm1"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := `@{RootModule='ScheduledTasks.psm1';ModuleVersion='1.0.0';GUID='7e4dbe58-e3a7-4b2f-a7e4-e50568cc1d9e';FunctionsToExport=@('Get-ScheduledTask')}`
	if err := os.WriteFile(filepath.Join(module, "ScheduledTasks.psd1"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SystemRoot", fakeRoot)
	t.Setenv("ProgramData", fakeRoot)
	t.Setenv("PSModulePath", modules)
	t.Setenv("COR_ENABLE_PROFILING", "1")
	t.Setenv("COR_PROFILER_PATH", filepath.Join(root, "must-not-load.dll"))
	t.Setenv("ProgramFiles", fakeRoot)
	t.Setenv("ProgramFiles(x86)", fakeRoot)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	executionStarted := time.Now()
	t.Cleanup(func() { retainNativeDiscoveryTiming(t, filepath.Join(root, "job", "process.log"), executionStarted) })
	data, err := execute(ctx, filepath.Join(root, "job"), Request{Action: "discover"})
	if err != nil {
		phases := []string{}
		if log, logErr := readWorkflowFile(filepath.Join(root, "job", "process.log"), 64<<10); logErr == nil {
			phases = nativeDiscoveryPhases(log)
		}
		t.Fatalf("read-only discovery failed: %v; context=%v; phases=%v", err, ctx.Err(), phases)
	}
	log, logErr := readWorkflowFile(filepath.Join(root, "job", "process.log"), 64<<10)
	if logErr != nil {
		t.Fatal("startup diagnostics were not retained")
	}
	position := -1
	for _, phase := range []string{"Workflow phase: input", "Workflow phase: parse", "Workflow phase: initialize", "Workflow phase: dispatch", "Discovery phase: services", "Discovery phase: complete"} {
		next := strings.Index(string(log), phase)
		if next <= position {
			t.Fatalf("missing or unordered fixed startup marker: %s", phase)
		}
		position = next
	}
	var result struct {
		OK   bool `json:"ok"`
		Data struct {
			ManagedRoot                string `json:"managedRoot"`
			RefreshTask                *bool  `json:"refreshTask"`
			RefreshTaskInspectionError string `json:"refreshTaskInspectionError"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if (result.Data.RefreshTask == nil) != (result.Data.RefreshTaskInspectionError != "") {
		t.Fatal("discovery confused an unknown scheduled-task state with a known result")
	}
	// Inspect the complete JSON because workflow result field nesting is stable
	// independently of this small projection and must never expose the fake root.
	if strings.Contains(string(data), fakeRoot) || !strings.Contains(string(data), strings.ReplaceAll(filepath.Join(expected, "AccessWeaver"), `\`, `\\`)) {
		t.Fatal("discovery used an environment-selected root")
	}
	if _, err := os.Stat(filepath.Join(module, "module-loaded.txt")); !os.IsNotExist(err) {
		t.Fatal("untrusted PowerShell module loaded", err)
	}
	if _, err := os.Stat(fakeRoot); !os.IsNotExist(err) {
		t.Fatal("discovery wrote attacker-selected machine storage", err)
	}
}

func nativeDiscoveryPhases(log []byte) []string {
	timing := regexp.MustCompile(`^(Workflow timing ms: (storage-ready|script-ready|request-ready|environment-ready|launch|first-output|child-exited|shell-input|shell-parse|shell-initialize|shell-dispatch)|Discovery timing ms: (services|components|applications|conflicts|refresh-task|final-paths|complete)|Task query timing ms: (start|started|capture-ready|exited|timed-out|drained|cleanup|tree-helper-returned|disposed)) [0-9]{1,12}$`)
	phases := []string{}
	for _, line := range strings.Split(string(log), "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case "Workflow phase: input", "Workflow phase: parse", "Workflow phase: initialize", "Workflow phase: dispatch", "Discovery phase: services", "Discovery phase: components", "Discovery phase: applications", "Discovery phase: conflicts", "Discovery phase: refresh-task", "Discovery phase: final-paths", "Discovery phase: complete":
			phases = append(phases, line)
		default:
			if timing.MatchString(line) {
				phases = append(phases, line)
			}
		}
		if len(phases) == 128 {
			break
		}
	}
	return phases
}

func retainNativeDiscoveryTiming(t *testing.T, logPath string, started time.Time) {
	t.Helper()
	directory := os.Getenv("ACCESSWEAVER_NATIVE_DISCOVERY_REPORT_DIR")
	if directory == "" {
		return
	}
	source := os.Getenv("GITHUB_SHA")
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(source) || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Error("discovery timing export requires an identified hosted native candidate")
		return
	}
	log, logErr := readWorkflowFile(logPath, 64<<10)
	record := map[string]any{"schemaVersion": 1, "sourceCommit": source, "target": "windows/" + runtime.GOARCH, "goVersion": runtime.Version(), "probeElapsedMilliseconds": time.Since(started).Milliseconds(), "testPassed": !t.Failed(), "logAvailable": logErr == nil, "phases": nativeDiscoveryPhases(log), "settingsChanged": false, "productionQualificationComplete": false}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Error(err)
		return
	}
	file, err := os.OpenFile(filepath.Join(directory, "discovery-windows-"+runtime.GOARCH+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	if err := json.NewEncoder(file).Encode(record); err != nil {
		t.Error(err)
	}
	if err := file.Close(); err != nil {
		t.Error(err)
	}
}

func TestNativeDiscoveryPhaseExportOmitsPrivateAndUnknownLines(t *testing.T) {
	log := strings.Join([]string{
		"PRIVATE_CREDENTIAL",
		"Workflow phase: dispatch",
		"Workflow timing ms: first-output 3",
		"Workflow timing ms: shell-parse 4",
		"Workflow timing ms: private-name 5",
		"Task query timing ms: start 12",
		"Task query timing ms: private-name 7",
		"Task query timing ms: start PRIVATE_CREDENTIAL",
		"Discovery timing ms: refresh-task 1234567890123",
		"Discovery phase: private-name",
		"Discovery timing ms: refresh-task 25",
	}, "\n")
	phases := nativeDiscoveryPhases([]byte(log))
	if strings.Join(phases, "|") != "Workflow phase: dispatch|Workflow timing ms: first-output 3|Workflow timing ms: shell-parse 4|Task query timing ms: start 12|Discovery timing ms: refresh-task 25" {
		t.Fatal("discovery export retained private, unknown or unbounded diagnostics")
	}
}
