//go:build windows

package nativepath

import (
	"os"
	"runtime"
	"testing"
)

func TestNativeWindowsArchitectureIgnoresEnvironment(t *testing.T) {
	before, err := WindowsArchitecture()
	if err != nil {
		t.Fatal(err)
	}
	// These jobs are required to execute natively; an emulated x64 process must
	// still report arm64 in product use, so GOARCH is only a hosted test oracle.
	if os.Getenv("GITHUB_ACTIONS") == "true" && before != runtime.GOARCH {
		t.Fatal("hosted architecture differs from the native build target")
	}
	for _, value := range []string{"x86", "AMD64", "ARM64", "unknown"} {
		t.Setenv("PROCESSOR_ARCHITECTURE", value)
		t.Setenv("PROCESSOR_ARCHITEW6432", value)
		got, err := WindowsArchitecture()
		if err != nil || got != before {
			t.Fatalf("environment changed OS architecture: %q, %v", got, err)
		}
	}
}
