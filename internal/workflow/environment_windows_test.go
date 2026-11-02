//go:build windows

package workflow

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	data, err := execute(ctx, filepath.Join(root, "job"), Request{Action: "discover"})
	if err != nil {
		phases := []string{}
		if log, logErr := readWorkflowFile(filepath.Join(root, "job", "process.log"), 64<<10); logErr == nil {
			for _, line := range strings.Split(string(log), "\n") {
				line = strings.TrimSpace(line)
				switch line {
				case "Workflow phase: input", "Workflow phase: parse", "Workflow phase: initialize", "Workflow phase: dispatch", "Discovery phase: services", "Discovery phase: components", "Discovery phase: applications", "Discovery phase: conflicts", "Discovery phase: refresh-task", "Discovery phase: final-paths", "Discovery phase: complete":
					phases = append(phases, line)
				}
			}
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
