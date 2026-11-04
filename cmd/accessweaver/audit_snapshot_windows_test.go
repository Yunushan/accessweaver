//go:build windows

package main

import (
	"encoding/hex"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAuditInputSnapshot(t *testing.T) {
	value, present := os.LookupEnv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST")
	if !present {
		t.Skip("requires explicit disposable hosted Windows audit storage opt-in")
	}
	if value != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Fatal("declared snapshot fixture requires opted-in hosted Windows context")
	}
	arch := runtime.GOARCH
	machine := map[string]uint16{"amd64": 0x8664, "arm64": 0xaa64}[arch]
	var process, native uint16
	if machine == 0 || windows.IsWow64Process2(windows.CurrentProcess(), &process, &native) != nil || process != 0 || native != machine || os.Getenv("ACCESSWEAVER_EXPECT_GOOS") != "windows" || os.Getenv("ACCESSWEAVER_EXPECT_GOARCH") != arch || os.Getenv("RUNNER_ARCH") != map[string]string{"amd64": "X64", "arm64": "ARM64"}[arch] {
		t.Fatal("snapshot fixture native target differs from declared source process")
	}
	if os.Getenv("GO_VERSION") == "" || runtime.Version() != "go"+os.Getenv("GO_VERSION") || os.Getenv("GOTOOLCHAIN") != "local" {
		t.Fatal("snapshot fixture SDK differs from local declared SDK")
	}
	commit, err := hex.DecodeString(os.Getenv("GITHUB_SHA"))
	if err != nil || len(commit) != 20 {
		t.Fatal("snapshot fixture source identity unavailable")
	}
	t.Cleanup(func() { retainAuditNativeReceipt(t, "snapshot", "source-built-native-audit-input-snapshots") })
	runAuditInputSnapshotTests(t)
}
