package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Registered before fixture directories so it observes their cleanup failures.
// These receipts describe source-built tests and contain no identity or path.
func retainAuditNativeReceipt(t *testing.T, name, scope string) {
	t.Helper()
	workspace := os.Getenv("GITHUB_WORKSPACE")
	source, err := hex.DecodeString(os.Getenv("GITHUB_SHA"))
	if runtime.GOOS != "windows" || os.Getenv("ACCESSWEAVER_DISPOSABLE_WINDOWS_AUDIT_STORAGE_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace || err != nil || len(source) != 20 || runtime.Version() != "go"+os.Getenv("GO_VERSION") || os.Getenv("GOTOOLCHAIN") != "local" {
		t.Error("native test receipt context unavailable")
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Error("native test receipt image unavailable")
		return
	}
	file, err := os.Open(executable)
	if err != nil {
		t.Error("native test receipt image read unavailable")
		return
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, io.LimitReader(file, (128<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || n < 1 || n > 128<<20 {
		t.Error("native test receipt image hashing failed")
		return
	}
	report := map[string]any{
		"schemaVersion": 1, "sourceCommit": os.Getenv("GITHUB_SHA"), "runID": os.Getenv("GITHUB_RUN_ID"), "testName": t.Name(),
		"platform": runtime.GOOS, "arch": runtime.GOARCH, "runtimeGoVersion": runtime.Version(), "runnerArch": os.Getenv("RUNNER_ARCH"),
		"runnerEnvironment": os.Getenv("RUNNER_ENVIRONMENT"), "imageOS": os.Getenv("ImageOS"), "imageVersion": os.Getenv("ImageVersion"),
		"testImageSHA256": hex.EncodeToString(hash.Sum(nil)), "passed": !t.Failed(), "scope": scope, "productionQualificationComplete": false,
	}
	payload, err := json.MarshalIndent(report, "", "  ")
	folder := filepath.Join(workspace, "build", "windows-audit-identity-input-checks")
	if err != nil || os.MkdirAll(folder, 0755) != nil || os.WriteFile(filepath.Join(folder, name+"-"+runtime.GOARCH+".json"), append(payload, '\n'), 0644) != nil {
		t.Error("native test receipt output unavailable")
	}
}
