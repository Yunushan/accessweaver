//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// Fixed source-owned temporary fixtures only: no installed app, registration,
// receipt, host profile, credential or executable is inspected or executed.
func TestDarwinDesktopReadCompletionContracts(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_DESKTOP_READ_TEST") != "1" {
		t.Skip("requires opted-in hosted root desktop fixture")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("native-desktop-read-guard")
	}
	cases := []struct {
		name string
		run  func(*testing.T, *runtimeReadCase)
	}{
		{"registration-close-sites", dvRegistrations}, {"registration-missing", dvMissing}, {"registration-body-cofailure", dvRegistrationBody},
		{"application-close-sites", dvApplication}, {"compatible-close-sites", dvCompatible}, {"application-body-cofailure", dvApplicationBody},
		{"applications-acquisition", dvAcquire}, {"receipt-absence-completion", dvReceipts}, {"result-completion-scope", dvScope},
		{"result-blocked-scope", dvBlocked}, {"result-panic-scope", dvPanic}, {"native-policy-refusal", dvPolicy},
	}
	var results []runtimeReadCase
	for _, item := range cases {
		c := runtimeReadCase{Name: item.name, Code: "none"}
		c.Passed = t.Run(item.name, func(t *testing.T) { item.run(t, &c) })
		results = append(results, c)
	}
	if !dvReport(results) {
		t.Error("desktop-read-report")
	}
}

type dvFixture struct {
	root, apps, app, registrations string
	record                         desktopRecord
	encoded                        []byte
}

func dvNew(t *testing.T, c *runtimeReadCase) *dvFixture {
	t.Helper()
	source := rrNew(t, c)
	root := t.TempDir()
	apps := filepath.Join(root, "Applications")
	app := filepath.Join(apps, "AccessWeaver.app")
	rrRequire(t, c, os.Mkdir(apps, 0755) == nil, "desktop-fixture-applications")
	rrRequire(t, c, os.Chmod(apps, 0755) == nil, "desktop-fixture-applications-mode")
	rrRequire(t, c, os.Rename(source.appPath, app) == nil, "desktop-fixture-owned-bundle")
	old := filepath.Join(app, "Contents/MacOS/accessweaver")
	binary := filepath.Join(app, "Contents/MacOS", desktopExecutable)
	rrRequire(t, c, os.Rename(old, binary) == nil, "desktop-fixture-inert-launcher")
	plistPath := filepath.Join(app, "Contents/Info.plist")
	plist, e := os.ReadFile(plistPath)
	rrRequire(t, c, e == nil, "desktop-fixture-plist")
	plist = bytes.ReplaceAll(plist, []byte(BundleID), []byte(desktopBundleID))
	plist = bytes.ReplaceAll(plist, []byte("<string>accessweaver</string>"), []byte("<string>"+desktopExecutable+"</string>"))
	rrWrite(t, c, plistPath, plist, 0644)
	record := desktopFixture()
	record.Build = source.build
	record.Manifest.Files = nil
	for _, name := range []string{"Contents/Info.plist", "Contents/MacOS/" + desktopExecutable, "Contents/Resources/BUILD-INFO.json"} {
		data, e := os.ReadFile(filepath.Join(app, name))
		rrRequire(t, c, e == nil, "desktop-fixture-payload")
		mode := "0644"
		if strings.Contains(name, "/MacOS/") {
			mode = "0755"
		}
		record.Manifest.Files = append(record.Manifest.Files, File{Path: name, Bytes: int64(len(data)), SHA256: digest(data), Mode: mode})
	}
	record.SBOM = strings.Replace(record.SBOM, `"content":"`+strings.Repeat("a", 64)+`"`, `"content":"`+record.Manifest.Files[1].SHA256+`"`, 1)
	record.SBOM = strings.Replace(record.SBOM, `"value":"amd64"`, `"value":"`+runtime.GOARCH+`"`, 1)
	encoded, e := json.Marshal(record)
	rrRequire(t, c, e == nil, "desktop-fixture-encoding")
	_, e = decodeDesktopRecord(encoded, runtime.GOARCH)
	rrRequire(t, c, e == nil, "desktop-fixture-record-contract")
	parent := t.TempDir()
	registration := filepath.Join(parent, desktopRoot)
	rrRequire(t, c, os.Mkdir(registration, 0755) == nil, "desktop-fixture-registration")
	rrRequire(t, c, os.Chmod(registration, 0755) == nil, "desktop-fixture-registration-mode")
	rrWrite(t, c, filepath.Join(registration, desktopRecordName(encoded)), encoded, 0644)
	return &dvFixture{root, apps, app, parent, record, encoded}
}
func dvRead(t *testing.T, c *runtimeReadCase, f *dvFixture, r runtimeReadOps) ([]desktopRecord, [][]byte, error) {
	t.Helper()
	return r.readDesktopRegistrationsAt(rrFile(t, c, f.registrations))
}
func dvSweep(t *testing.T, c *runtimeReadCase, run func(runtimeReadOps) error, unchanged func()) {
	t.Helper()
	n := 0
	r := nativeRuntimeReads()
	r.closeFile = func(f *os.File) error { n++; return f.Close() }
	rrRequire(t, c, run(r) == nil && n > 0 && n <= 128, "desktop-close-baseline")
	c.Sites = n
	for target := 1; target <= n; target++ {
		count := 0
		owned := map[*os.File]int{}
		cause := errors.New("fixed desktop cleanup cofactor")
		r.closeFile = func(f *os.File) error {
			count++
			owned[f]++
			e := f.Close()
			if count == target {
				return errors.Join(e, cause)
			}
			return e
		}
		e := run(r)
		rrRequire(t, c, errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain), "desktop-close-failure-retained")
		rrClosed(t, c, owned)
		unchanged()
	}
}
func dvRegistrations(t *testing.T, c *runtimeReadCase) {
	f := dvNew(t, c)
	before := rrSnapshot(t, c, f.registrations)
	dvSweep(t, c, func(r runtimeReadOps) error {
		records, data, e := dvRead(t, c, f, r)
		if e != nil {
			rrRequire(t, c, records == nil && data == nil, "desktop-unconfirmed-records-withheld")
		} else {
			rrRequire(t, c, len(records) == 1 && len(data) == 1 && reflect.DeepEqual(records[0], f.record) && bytes.Equal(data[0], f.encoded), "desktop-registration-confirmed")
		}
		return e
	}, func() {
		rrRequire(t, c, reflect.DeepEqual(before, rrSnapshot(t, c, f.registrations)), "desktop-registration-mutated")
	})
}
func dvMissing(t *testing.T, c *runtimeReadCase) {
	path := t.TempDir()
	records, data, e := nativeRuntimeReads().readDesktopRegistrationsAt(rrFile(t, c, path))
	rrRequire(t, c, e == nil && records == nil && data == nil, "desktop-clean-absence-allowed")
	cause := errors.New("fixed missing registration cleanup cofactor")
	r := nativeRuntimeReads()
	owned := map[*os.File]int{}
	r.closeFile = func(f *os.File) error { owned[f]++; return errors.Join(f.Close(), cause) }
	records, data, e = r.readDesktopRegistrationsAt(rrFile(t, c, path))
	rrRequire(t, c, records == nil && data == nil && errors.Is(e, cause) && errors.Is(e, unix.ENOENT) && !darwintrust.IsReadAbsent(e), "desktop-missing-cleanup-not-absence")
	rrClosed(t, c, owned)
}
func dvRegistrationBody(t *testing.T, c *runtimeReadCase) {
	f := dvNew(t, c)
	rrWrite(t, c, filepath.Join(f.registrations, desktopRoot, "unknown"), []byte("fixed retained evidence"), 0644)
	before := rrSnapshot(t, c, f.registrations)
	cause := errors.New("fixed registration body cleanup cofactor")
	r := nativeRuntimeReads()
	parent := rrFile(t, c, f.registrations)
	r.closeFile = func(f *os.File) error {
		e := f.Close()
		if f == parent {
			return errors.Join(e, cause)
		}
		return e
	}
	records, data, e := r.readDesktopRegistrationsAt(parent)
	rrRequire(t, c, records == nil && data == nil && errors.Is(e, cause) && rrMessage(e, "unknown desktop registration object; preserve and inspect") && reflect.DeepEqual(before, rrSnapshot(t, c, f.registrations)), "desktop-registration-body-and-cleanup")
}
func dvApplication(t *testing.T, c *runtimeReadCase) { dvVerifySweep(t, c, false) }
func dvCompatible(t *testing.T, c *runtimeReadCase)  { dvVerifySweep(t, c, true) }
func dvVerifySweep(t *testing.T, c *runtimeReadCase, compatible bool) {
	f := dvNew(t, c)
	apps := rrFile(t, c, f.apps)
	before := rrSnapshot(t, c, f.root)
	dvSweep(t, c, func(r runtimeReadOps) error {
		var e error
		if compatible {
			e = r.desktopApplicationCompatible(apps, []desktopRecord{f.record})
		} else {
			e = r.verifyDesktopApplication(apps, f.record)
		}
		rrLive(t, c, apps)
		return e
	}, func() {
		rrRequire(t, c, reflect.DeepEqual(before, rrSnapshot(t, c, f.root)), "desktop-public-application-mutated")
	})
}
func dvApplicationBody(t *testing.T, c *runtimeReadCase) {
	f := dvNew(t, c)
	apps := rrFile(t, c, f.apps)
	record := f.record
	record.Build.Version = "0.1.1-alpha"
	cause := errors.New("fixed public build cleanup cofactor")
	r := nativeRuntimeReads()
	owned := map[*os.File]int{}
	r.closeFile = func(file *os.File) error {
		owned[file]++
		e := file.Close()
		if file.Name() == f.app {
			return errors.Join(e, cause)
		}
		return e
	}
	e := r.verifyDesktopApplication(apps, record)
	rrRequire(t, c, errors.Is(e, cause) && rrMessage(e, "public desktop build differs from protected registration"), "desktop-application-body-and-cleanup")
	rrClosed(t, c, owned)
	rrLive(t, c, apps)
}
func dvAcquire(t *testing.T, c *runtimeReadCase) {
	f := dvNew(t, c)
	root := rrFile(t, c, f.root)
	apps, e := nativeRuntimeReads().applicationsAt(root)
	rrRequire(t, c, e == nil && apps != nil, "desktop-container-handoff")
	rrClosed(t, c, map[*os.File]int{root: 1})
	rrLive(t, c, apps)
	rrRequire(t, c, apps.Close() == nil, "desktop-fixture-container-close")
	root = rrFile(t, c, f.root)
	r := nativeRuntimeReads()
	owned := map[*os.File]int{}
	a := errors.New("fixed root close cofactor")
	b := errors.New("fixed successor close cofactor")
	r.closeFile = func(file *os.File) error {
		owned[file]++
		e := file.Close()
		if file == root {
			return errors.Join(e, a)
		}
		return errors.Join(e, b)
	}
	apps, e = r.applicationsAt(root)
	rrRequire(t, c, apps == nil && errors.Is(e, a) && errors.Is(e, b) && len(owned) == 2, "desktop-container-successor-disposed")
	rrClosed(t, c, owned)
	rrRequire(t, c, os.Chmod(f.apps, 0700) == nil, "desktop-fixture-invalid-container-mode")
	root = rrFile(t, c, f.root)
	owned = map[*os.File]int{}
	apps, e = r.applicationsAt(root)
	rrRequire(t, c, apps == nil && rrMessage(e, "unsupported Applications container protection") && errors.Is(e, a) && errors.Is(e, b), "desktop-container-policy-and-cleanup")
	rrClosed(t, c, owned)
}
func dvReceipts(t *testing.T, c *runtimeReadCase) {
	path := t.TempDir()
	r := nativeRuntimeReads()
	rrRequire(t, c, r.legacyReceiptsAbsentAt(rrFile(t, c, path)) == nil, "desktop-receipt-clean-absence")
	cause := errors.New("fixed receipt metadata cleanup cofactor")
	r.closeFile = func(f *os.File) error { return errors.Join(f.Close(), cause) }
	e := r.legacyReceiptsAbsentAt(rrFile(t, c, path))
	rrRequire(t, c, errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain), "desktop-receipt-absence-unconfirmed")
	rrWrite(t, c, filepath.Join(path, BundleID+".plist"), []byte("fixed inert legacy receipt"), 0644)
	before := rrSnapshot(t, c, path)
	e = r.legacyReceiptsAbsentAt(rrFile(t, c, path))
	rrRequire(t, c, rrMessage(e, "legacy receipt exists; explicit migration is required") && errors.Is(e, cause) && reflect.DeepEqual(before, rrSnapshot(t, c, path)), "desktop-receipt-body-and-cleanup")
}
func dvResult(f *dvFixture) DesktopPackageResult {
	return DesktopPackageResult{SchemaVersion: 1, Component: "application", Phase: "postinstall", Version: f.record.Build.Version, RecordSHA256: digest(f.encoded), PublicApplicationVerified: true}
}
func dvScope(t *testing.T, c *runtimeReadCase) {
	f := dvNew(t, c)
	r := nativeRuntimeReads()
	apps := rrFile(t, c, f.apps)
	result, e := r.withDesktopApplications(apps, func(apps *os.File) (DesktopPackageResult, error) {
		return dvResult(f), r.verifyDesktopApplication(apps, f.record)
	})
	rrRequire(t, c, e == nil && result.PublicApplicationVerified, "desktop-confirmed-result")
	rrClosed(t, c, map[*os.File]int{apps: 1})
	apps = rrFile(t, c, f.apps)
	cause := errors.New("fixed final applications cleanup cofactor")
	r.closeFile = func(file *os.File) error {
		e := file.Close()
		if file == apps {
			return errors.Join(e, cause)
		}
		return e
	}
	result, e = r.withDesktopApplications(apps, func(apps *os.File) (DesktopPackageResult, error) {
		return dvResult(f), r.verifyDesktopApplication(apps, f.record)
	})
	rrRequire(t, c, result == (DesktopPackageResult{}) && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain), "desktop-unconfirmed-result-withheld")
	apps = rrFile(t, c, f.apps)
	body := errors.New("fixed verification body cofactor")
	result, e = r.withDesktopApplications(apps, func(*os.File) (DesktopPackageResult, error) { return dvResult(f), body })
	rrRequire(t, c, result == (DesktopPackageResult{}) && errors.Is(e, body) && errors.Is(e, cause), "desktop-scope-multiple-causes")
}
func dvBlocked(t *testing.T, c *runtimeReadCase) {
	f := dvNew(t, c)
	apps := rrFile(t, c, f.apps)
	r := nativeRuntimeReads()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cause := errors.New("fixed blocked desktop cleanup cofactor")
	r.closeFile = func(file *os.File) error {
		if file == apps {
			close(entered)
			<-release
			return errors.Join(file.Close(), cause)
		}
		return file.Close()
	}
	type response struct {
		value DesktopPackageResult
		err   error
	}
	done := make(chan response, 1)
	joined := false
	go func() {
		value, e := r.withDesktopApplications(apps, func(apps *os.File) (DesktopPackageResult, error) {
			return dvResult(f), r.verifyDesktopApplication(apps, f.record)
		})
		done <- response{value, e}
	}()
	defer func() {
		unblock()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("desktop-worker-not-joined")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		rrRequire(t, c, false, "desktop-cleanup-boundary-not-entered")
	}
	select {
	case <-done:
		joined = true
		rrRequire(t, c, false, "desktop-result-returned-before-cleanup")
	default:
	}
	unblock()
	select {
	case result := <-done:
		joined = true
		rrRequire(t, c, result.value == (DesktopPackageResult{}) && errors.Is(result.err, cause), "desktop-blocked-result-withheld")
	case <-time.After(5 * time.Second):
		rrRequire(t, c, false, "desktop-worker-not-joined")
	}
}
func dvPanic(t *testing.T, c *runtimeReadCase) {
	f := dvNew(t, c)
	apps := rrFile(t, c, f.apps)
	r := nativeRuntimeReads()
	owned := map[*os.File]int{}
	r.closeFile = func(file *os.File) error { owned[file]++; return file.Close() }
	recovered := false
	func() {
		defer func() { recovered = recover() == "fixed desktop verification panic" }()
		_, _ = r.withDesktopApplications(apps, func(*os.File) (DesktopPackageResult, error) { panic("fixed desktop verification panic") })
	}()
	rrRequire(t, c, recovered && len(owned) == 1, "desktop-panic-preserved")
	rrClosed(t, c, owned)
}
func dvPolicy(t *testing.T, c *runtimeReadCase) {
	f := dvNew(t, c)
	rrRequire(t, c, os.Chown(f.apps, 0, 80) == nil && os.Chmod(f.apps, 0775) == nil, "desktop-fixture-admin-container")
	apps, e := nativeRuntimeReads().applicationsAt(rrFile(t, c, f.root))
	rrRequire(t, c, e == nil && apps != nil, "desktop-existing-admin-exception")
	rrRequire(t, c, nativeRuntimeReads().verifyDesktopApplication(apps, f.record) == nil, "desktop-admin-container-strict-descendants")
	rrRequire(t, c, os.Chown(f.app, 0, 80) == nil, "desktop-fixture-untrusted-app-group")
	rrRequire(t, c, nativeRuntimeReads().verifyDesktopApplication(apps, f.record) != nil, "desktop-admin-exception-not-inherited")
	rrRequire(t, c, apps.Close() == nil, "desktop-fixture-admin-close")
	path := t.TempDir()
	rrRequire(t, c, os.Symlink(f.apps, filepath.Join(path, "Applications")) == nil, "desktop-fixture-container-alias")
	apps, e = nativeRuntimeReads().applicationsAt(rrFile(t, c, path))
	rrRequire(t, c, e != nil && apps == nil, "desktop-container-alias-refused")
}
func dvReport(cases []runtimeReadCase) bool {
	source := os.Getenv("GITHUB_SHA")
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) {
		return false
	}
	outcome := "passed"
	for _, c := range cases {
		if !c.Passed {
			outcome = "failed"
		}
	}
	value := struct {
		SchemaVersion            int               `json:"schemaVersion"`
		SourceCommit             string            `json:"sourceCommit"`
		GOOS                     string            `json:"goos"`
		GOARCH                   string            `json:"goarch"`
		GoVersion                string            `json:"goVersion"`
		Outcome                  string            `json:"outcome"`
		Cases                    []runtimeReadCase `json:"cases"`
		NativeRootFixture        bool              `json:"nativeRootFixture"`
		NativeInstalledQualified bool              `json:"nativeInstalledQualified"`
	}{1, source, runtime.GOOS, runtime.GOARCH, runtime.Version(), outcome, cases, true, false}
	data, e := json.Marshal(value)
	if e != nil || len(data) > 16384 {
		return false
	}
	line := "DESKTOP-READ-RESULT " + string(data) + "\n"
	n, e := io.WriteString(os.Stdout, line)
	return n == len(line) && e == nil
}
