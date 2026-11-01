package nativepath

import (
	"strings"
	"testing"
)

func TestCleanEnvironmentRemovesInjectionAndKeepsUserIdentity(t *testing.T) {
	original := []string{"Path=untrusted", "SystemROOT=untrusted", "ProgramData=untrusted", "PSModulePath=untrusted", "COR_ENABLE_PROFILING=1", "COR_PROFILER_PATH=untrusted.dll", "COMPlus_EnableDiagnostics=1", "DOTNET_STARTUP_HOOKS=untrusted.dll", "LUA_PATH=untrusted", "NODE_OPTIONS=--require untrusted", "USERPROFILE=desktop-user", "LOCALAPPDATA=user-applications", "=C:=untrusted", "bad-entry"}
	result := cleanEnvironment(original, []string{"PATH=trusted-system", "SystemRoot=trusted-windows"})
	joined := strings.Join(result, "\n")
	if strings.Contains(joined, "untrusted") || strings.Contains(joined, "PROFILING") || strings.Contains(joined, "bad-entry") {
		t.Fatal("untrusted process inputs retained", joined)
	}
	if !strings.Contains(joined, "USERPROFILE=desktop-user") || !strings.Contains(joined, "LOCALAPPDATA=user-applications") || !strings.Contains(joined, "PATH=trusted-system") {
		t.Fatal("required identity/system environment lost", joined)
	}
}
