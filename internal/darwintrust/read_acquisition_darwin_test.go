//go:build darwin && (amd64 || arm64)

package darwintrust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type readAcquisitionCase struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Checks int    `json:"checks"`
	Code   string `json:"code"`
}

func acquisitionRequire(t *testing.T, result *readAcquisitionCase, ok bool, code string) {
	t.Helper()
	result.Checks++
	if !ok {
		result.Code = code
		t.Fatal(code)
	}
}

// Each case uses its own native APFS fixture and per-call callback. Faults are
// semantic cofactors after real Close; no host root, policy, installed runtime,
// process image, ACL reset or system path is substituted or mutated by this suite.
func TestDarwinReadAcquisitionContracts(t *testing.T) {
	var results []readAcquisitionCase
	cases := []struct {
		name string
		run  func(*testing.T, *readAcquisitionCase)
	}{
		{"initial-check", acquisitionInitialCheck},
		{"root-transfer", acquisitionRootTransfer},
		{"multi-hop-transfer", acquisitionMultiHop},
		{"predecessor-close", acquisitionPredecessorFailure},
		{"missing-close", acquisitionMissingClose},
		{"missing", acquisitionMissing},
		{"rejected-child", acquisitionRejectedChild},
		{"link", acquisitionLink},
		{"synchronous", acquisitionSynchronous},
		{"regular-reject", acquisitionRegularReject},
		{"absence-classification", acquisitionAbsenceClassification},
	}
	for _, c := range cases {
		result := readAcquisitionCase{Name: c.name, Code: "none"}
		result.Passed = t.Run(c.name, func(t *testing.T) { c.run(t, &result) })
		results = append(results, result)
	}
	if !writeAcquisitionReport(results) {
		t.Error("report-completion")
	}
}

func acquisitionFixture(t *testing.T, r *readAcquisitionCase) (*os.File, *os.File, string, uint32) {
	t.Helper()
	path := t.TempDir()
	parent, err := os.Open(path)
	acquisitionRequire(t, r, err == nil, "fixture-open")
	t.Cleanup(func() {
		if parent.Close() != nil {
			t.Error("fixture-borrowed-close")
		}
	})
	owner := uint32(os.Geteuid())
	_, err = Check(parent, true, owner)
	acquisitionRequire(t, r, err == nil, "fixture-native-check")
	owned, err := os.Open(path)
	acquisitionRequire(t, r, err == nil, "fixture-owned-open")
	// Closing an already released os.File is safe and never closes a reused raw
	// descriptor. This fallback owns only this fixture's os.File wrapper.
	t.Cleanup(func() { _ = owned.Close() })
	return parent, owned, path, owner
}
func acquisitionChild(t *testing.T, r *readAcquisitionCase, path, name string, mode os.FileMode) {
	t.Helper()
	err := os.Mkdir(filepath.Join(path, name), mode)
	acquisitionRequire(t, r, err == nil, "fixture-mkdir")
	err = os.Chmod(filepath.Join(path, name), mode)
	acquisitionRequire(t, r, err == nil, "fixture-mode")
}
func acquisitionClosed(t *testing.T, r *readAcquisitionCase, file *os.File) {
	t.Helper()
	_, err := file.Stat()
	acquisitionRequire(t, r, errors.Is(err, os.ErrClosed), "owned-file-not-closed")
}
func acquisitionBorrowed(t *testing.T, r *readAcquisitionCase, file *os.File) {
	t.Helper()
	_, err := file.Stat()
	acquisitionRequire(t, r, err == nil, "borrowed-file-closed")
}
func acquisitionInitialCheck(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, path, owner := acquisitionFixture(t, r)
	err := os.Chmod(path, 0777)
	acquisitionRequire(t, r, err == nil, "fixture-mode")
	defer func() {
		if os.Chmod(path, 0700) != nil {
			t.Error("fixture-mode-restore")
		}
	}()
	closed := errors.New("fixed initial cleanup cofactor")
	calls := 0
	got, err := walkReadDirectories(owned, nil, owner, func(f *os.File) error { calls++; return errors.Join(f.Close(), closed) })
	acquisitionRequire(t, r, got == nil && errors.Is(err, ErrReadCleanupUncertain) && errors.Is(err, closed) && calls == 1, "initial-inspection-cleanup")
	acquisitionClosed(t, r, owned)
	acquisitionBorrowed(t, r, borrowed)
}
func acquisitionRootTransfer(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, _, owner := acquisitionFixture(t, r)
	calls := 0
	got, err := walkReadDirectories(owned, nil, owner, func(f *os.File) error { calls++; return f.Close() })
	acquisitionRequire(t, r, err == nil && got == owned && calls == 0, "root-ownership-transfer")
	acquisitionBorrowed(t, r, got)
	acquisitionBorrowed(t, r, borrowed)
	acquisitionRequire(t, r, got.Close() == nil, "caller-final-close")
}
func acquisitionMultiHop(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, path, owner := acquisitionFixture(t, r)
	acquisitionChild(t, r, path, "one", 0755)
	acquisitionChild(t, r, filepath.Join(path, "one"), "two", 0755)
	var closed []*os.File
	got, err := walkReadDirectories(owned, []string{"one", "two"}, owner, func(f *os.File) error { closed = append(closed, f); return f.Close() })
	acquisitionRequire(t, r, err == nil && got != nil && len(closed) == 2 && closed[0] == owned && closed[1] != owned, "multi-hop-transfer")
	defer func() { _ = got.Close() }()
	for _, f := range closed {
		acquisitionClosed(t, r, f)
	}
	acquisitionBorrowed(t, r, got)
	acquisitionBorrowed(t, r, borrowed)
	actual, aerr := got.Stat()
	named, nerr := os.Stat(filepath.Join(path, "one", "two"))
	acquisitionRequire(t, r, aerr == nil && nerr == nil && os.SameFile(actual, named), "transferred-final-identity")
	acquisitionRequire(t, r, got.Close() == nil, "caller-final-close")
}
func acquisitionPredecessorFailure(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, path, owner := acquisitionFixture(t, r)
	acquisitionChild(t, r, path, "one", 0755)
	parentCause := errors.New("fixed predecessor cleanup cofactor")
	nextCause := errors.New("fixed successor cleanup cofactor")
	counts := map[*os.File]int{}
	got, err := walkReadDirectories(owned, []string{"one"}, owner, func(f *os.File) error {
		counts[f]++
		cause := nextCause
		if f == owned {
			cause = parentCause
		}
		return errors.Join(f.Close(), cause)
	})
	acquisitionRequire(t, r, got == nil && errors.Is(err, ErrReadCleanupUncertain) && errors.Is(err, parentCause) && errors.Is(err, nextCause) && len(counts) == 2, "successor-cleanup-cofailure")
	for f, n := range counts {
		acquisitionRequire(t, r, n == 1, "native-close-not-once")
		acquisitionClosed(t, r, f)
	}
	acquisitionBorrowed(t, r, borrowed)
}
func acquisitionMissingClose(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, _, owner := acquisitionFixture(t, r)
	cause := errors.New("fixed missing cleanup cofactor")
	calls := 0
	got, err := walkReadDirectories(owned, []string{"missing"}, owner, func(f *os.File) error { calls++; return errors.Join(f.Close(), cause) })
	acquisitionRequire(t, r, got == nil && errors.Is(err, unix.ENOENT) && errors.Is(err, ErrReadCleanupUncertain) && errors.Is(err, cause) && calls == 1, "missing-with-cleanup-cause")
	acquisitionRequire(t, r, !IsReadAbsent(err), "cleanup-precedes-absence")
	acquisitionClosed(t, r, owned)
	acquisitionBorrowed(t, r, borrowed)
}
func acquisitionMissing(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, path, owner := acquisitionFixture(t, r)
	calls := 0
	got, err := walkReadDirectories(owned, []string{"missing"}, owner, func(f *os.File) error { calls++; return f.Close() })
	acquisitionRequire(t, r, got == nil && IsReadAbsent(err) && !errors.Is(err, ErrReadCleanupUncertain) && calls == 1, "confirmed-missing-preserved")
	entries, readErr := os.ReadDir(path)
	acquisitionRequire(t, r, readErr == nil && len(entries) == 0, "missing-read-created-state")
	acquisitionClosed(t, r, owned)
	acquisitionBorrowed(t, r, borrowed)
}
func acquisitionRejectedChild(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, path, owner := acquisitionFixture(t, r)
	acquisitionChild(t, r, path, "unsafe", 0777)
	a := errors.New("fixed rejected child cleanup cofactor")
	b := errors.New("fixed parent cleanup cofactor")
	counts := map[*os.File]int{}
	got, err := walkReadDirectories(owned, []string{"unsafe"}, owner, func(f *os.File) error {
		counts[f]++
		cause := a
		if f == owned {
			cause = b
		}
		return errors.Join(f.Close(), cause)
	})
	acquisitionRequire(t, r, got == nil && errors.Is(err, a) && errors.Is(err, b) && errors.Is(err, ErrReadCleanupUncertain) && len(counts) == 2, "rejected-child-and-parent-cleanup")
	for f, n := range counts {
		acquisitionRequire(t, r, n == 1, "native-close-not-once")
		acquisitionClosed(t, r, f)
	}
	acquisitionBorrowed(t, r, borrowed)
}
func acquisitionLink(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, path, owner := acquisitionFixture(t, r)
	acquisitionChild(t, r, path, "target", 0755)
	err := os.Symlink("target", filepath.Join(path, "link"))
	acquisitionRequire(t, r, err == nil, "fixture-link")
	calls := 0
	got, err := walkReadDirectories(owned, []string{"link"}, owner, func(f *os.File) error { calls++; return f.Close() })
	acquisitionRequire(t, r, got == nil && err != nil && !IsReadAbsent(err) && !errors.Is(err, ErrReadCleanupUncertain) && calls == 1, "nofollow-link-refusal")
	link, err := os.Readlink(filepath.Join(path, "link"))
	acquisitionRequire(t, r, err == nil && link == "target", "refusal-changed-link")
	acquisitionClosed(t, r, owned)
	acquisitionBorrowed(t, r, borrowed)
}
func acquisitionSynchronous(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, path, owner := acquisitionFixture(t, r)
	acquisitionChild(t, r, path, "one", 0755)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	type result struct {
		file *os.File
		err  error
	}
	done := make(chan result, 1)
	cause := errors.New("fixed synchronous cleanup cofactor")
	go func() {
		file, err := walkReadDirectories(owned, []string{"one"}, owner, func(f *os.File) error {
			if f == owned {
				close(entered)
				<-release
				return errors.Join(f.Close(), cause)
			}
			return f.Close()
		})
		done <- result{file, err}
	}()
	// Always join the owned worker even when the entry assertion fails.
	joined := false
	defer func() {
		unblock()
		if !joined {
			select {
			case out := <-done:
				if out.file != nil {
					_ = out.file.Close()
				}
			case <-time.After(5 * time.Second):
				t.Error("owned-worker-not-joined")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		acquisitionRequire(t, r, false, "close-boundary-not-entered")
	}
	select {
	case out := <-done:
		joined = true
		if out.file != nil {
			_ = out.file.Close()
		}
		acquisitionRequire(t, r, false, "returned-before-close-completion")
	default:
	}
	acquisitionBorrowed(t, r, owned)
	unblock()
	select {
	case out := <-done:
		joined = true
		acquisitionRequire(t, r, out.file == nil && errors.Is(out.err, cause) && errors.Is(out.err, ErrReadCleanupUncertain), "blocked-close-outcome")
	case <-time.After(5 * time.Second):
		acquisitionRequire(t, r, false, "owned-worker-not-joined")
	}
	acquisitionClosed(t, r, owned)
	acquisitionBorrowed(t, r, borrowed)
}
func acquisitionRegularReject(t *testing.T, r *readAcquisitionCase) {
	borrowed, owned, path, owner := acquisitionFixture(t, r)
	acquisitionRequire(t, r, owned.Close() == nil, "fixture-owned-close")
	path = filepath.Join(path, "regular")
	err := os.WriteFile(path, []byte("fixed fixture"), 0666)
	acquisitionRequire(t, r, err == nil, "fixture-write")
	acquisitionRequire(t, r, os.Chmod(path, 0666) == nil, "fixture-mode")
	file, err := os.Open(path)
	acquisitionRequire(t, r, err == nil, "fixture-open")
	defer func() { _ = file.Close() }()
	_, body := Check(file, false, owner)
	acquisitionRequire(t, r, body != nil, "native-regular-inspection")
	cause := errors.New("fixed regular cleanup cofactor")
	calls := 0
	err = closeReadAcquisition(file, body, func(f *os.File) error { calls++; return errors.Join(f.Close(), cause) })
	acquisitionRequire(t, r, errors.Is(err, body) && errors.Is(err, cause) && errors.Is(err, ErrReadCleanupUncertain) && calls == 1, "regular-inspection-cleanup-cause")
	acquisitionClosed(t, r, file)
	acquisitionBorrowed(t, r, borrowed)
}
func acquisitionAbsenceClassification(t *testing.T, r *readAcquisitionCase) {
	acquisitionRequire(t, r, !IsReadAbsent(nil) && IsReadAbsent(unix.ENOENT) && !IsReadAbsent(unix.EACCES), "ordinary-absence-classification")
	acquisitionRequire(t, r, !IsReadAbsent(errors.Join(unix.ENOENT, ErrReadCleanupUncertain)) && !IsReadAbsent(errors.Join(ErrReadCleanupUncertain, errors.Join(unix.ENOENT, unix.EBADF))), "nested-cleanup-precedence")
}

// Optional source-owned CI report. No paths, owners, native errors, file data,
// process/account information or host security metadata enter this schema.
func writeAcquisitionReport(cases []readAcquisitionCase) bool {
	parent := os.Getenv("ACCESSWEAVER_DARWIN_READ_ACQUISITION_REPORT")
	if parent == "" {
		return true
	}
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return false
	}
	before, err := os.Lstat(parent)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return false
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		return false
	}
	commit := os.Getenv("GITHUB_SHA")
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return false
	}
	sources := map[string]string{}
	for _, name := range []string{"files_darwin.go", "read_acquisition_darwin_test.go"} {
		data, err := os.ReadFile(name)
		if err != nil || len(data) > 65536 {
			return false
		}
		hash := sha256.Sum256(data)
		sources[name] = hex.EncodeToString(hash[:])
	}
	outcome := "passed"
	for _, c := range cases {
		if !c.Passed {
			outcome = "failed"
		}
	}
	report := struct {
		SchemaVersion            int                   `json:"schemaVersion"`
		SourceCommit             string                `json:"sourceCommit"`
		SourceSHA256             map[string]string     `json:"sourceSHA256"`
		GOOS                     string                `json:"goos"`
		GOARCH                   string                `json:"goarch"`
		GoVersion                string                `json:"goVersion"`
		Outcome                  string                `json:"outcome"`
		Cases                    []readAcquisitionCase `json:"cases"`
		NativeInstalledQualified bool                  `json:"nativeInstalledQualified"`
	}{1, commit, sources, runtime.GOOS, runtime.GOARCH, runtime.Version(), outcome, cases, false}
	data, err := json.Marshal(report)
	if err != nil || len(data) > 8192 {
		return false
	}
	after, err := os.Lstat(parent)
	if err != nil || !os.SameFile(before, after) || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 {
		return false
	}
	file, err := os.OpenFile(filepath.Join(parent, "darwin-read-acquisition.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return false
	}
	n, writeErr := file.Write(data)
	closeErr := file.Close()
	return n == len(data) && writeErr == nil && closeErr == nil
}
