//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

type runtimeReadCase struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Checks int    `json:"checks"`
	Code   string `json:"code"`
	Sites  int    `json:"sites"`
}

func rrRequire(t *testing.T, c *runtimeReadCase, ok bool, code string) {
	t.Helper()
	c.Checks++
	if !ok {
		c.Code = code
		t.Fatal(code)
	}
}

// This opt-in is the same disposable hosted-root fixture model used by the
// package driver. Every object is new temporary fixture data; no installed app,
// receipt, policy, user profile, certificate, process image or payload executes.
func TestDarwinRuntimeReadCompletionContracts(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_RUNTIME_READ_TEST") != "1" {
		t.Skip("requires opted-in hosted root reader fixture")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("native-runtime-read-guard")
	}
	var results []runtimeReadCase
	cases := []struct {
		name string
		run  func(*testing.T, *runtimeReadCase)
	}{
		{"active-runtime", rrActive},
		{"read-close-sites", rrReadCloseSites},
		{"missing-cofailure", rrMissingCofailure},
		{"bounded-cofailure", rrBoundedCofailure},
		{"successor-cofailure", rrSuccessorCofailure},
		{"seal-refusal", rrSealRefusal},
		{"scope-transfer", rrScopeTransfer},
		{"scope-close-sites", rrScopeCloseSites},
		{"scope-cofailure", rrScopeCofailure},
		{"scope-blocked", rrScopeBlocked},
		{"scope-panic", rrScopePanic},
		{"inherited-transfer", rrInheritedTransfer},
		{"inherited-cofailure", rrInheritedCofailure},
		{"foreign-descriptor", rrForeignDescriptor},
		{"parse-and-busy", rrParseAndBusy},
		{"authority-and-identity", rrAuthorityAndIdentity},
	}
	for _, item := range cases {
		c := runtimeReadCase{Name: item.name, Code: "none"}
		c.Passed = t.Run(item.name, func(t *testing.T) { item.run(t, &c) })
		results = append(results, c)
	}
	if !rrReport(results) {
		t.Error("runtime-read-report-completion")
	}
}

type rrFixture struct {
	parentPath, appPath, corePath string
	parent, root                  *os.File
	slot                          deploymentSlot
	build                         buildinfo.Info
}

func rrFile(t *testing.T, c *runtimeReadCase, path string) *os.File {
	t.Helper()
	f, e := os.Open(path)
	rrRequire(t, c, e == nil, "fixture-open")
	// The fallback closes this os.File wrapper only. Repeated wrapper Close never
	// closes a reused raw descriptor; production completion callbacks run once.
	t.Cleanup(func() {
		if e := f.Close(); e != nil && !errors.Is(e, os.ErrClosed) {
			t.Error("fixture-file-close")
		}
	})
	return f
}
func rrWrite(t *testing.T, c *runtimeReadCase, path string, data []byte, mode os.FileMode) {
	t.Helper()
	rrRequire(t, c, os.WriteFile(path, data, mode) == nil, "fixture-write")
	rrRequire(t, c, os.Chmod(path, mode) == nil, "fixture-mode")
}
func rrNew(t *testing.T, c *runtimeReadCase) *rrFixture {
	t.Helper()
	base := t.TempDir()
	id := strings.Repeat("1", 32)
	root := filepath.Join(base, deploymentRoot)
	slotPath := filepath.Join(root, "versions", id)
	app := filepath.Join(slotPath, "AccessWeaver.app")
	for _, path := range []string{root, filepath.Join(root, "state"), filepath.Join(root, "versions"), slotPath, app, filepath.Join(app, "Contents"), filepath.Join(app, "Contents", "MacOS"), filepath.Join(app, "Contents", "Resources")} {
		rrRequire(t, c, os.Mkdir(path, 0755) == nil, "fixture-directory")
		rrRequire(t, c, os.Chmod(path, 0755) == nil, "fixture-directory-mode")
	}
	core := make([]byte, 32)
	binary.LittleEndian.PutUint32(core, 0xfeedfacf)
	cpu := uint32(0x01000007)
	if runtime.GOARCH == "arm64" {
		cpu = 0x0100000c
	}
	binary.LittleEndian.PutUint32(core[4:], cpu)
	binary.LittleEndian.PutUint32(core[12:], 2)
	build := buildinfo.Info{Version: "0.1.0-alpha", Commit: strings.Repeat("a", 40), SourceState: "clean", BuiltAt: "2026-11-01T00:00:00Z", GoVersion: runtime.Version(), Platform: "darwin", Arch: runtime.GOARCH}
	buildData, e := json.Marshal(build)
	rrRequire(t, c, e == nil, "fixture-build")
	plist := []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.github.yunushan.accessweaver</string><key>CFBundleExecutable</key><string>accessweaver</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>0.1.0</string><key>CFBundleShortVersionString</key><string>0.1.0</string><key>AccessWeaverReleaseVersion</key><string>0.1.0-alpha</string><key>LSUIElement</key><true/></dict></plist>`)
	payloads := []struct {
		name string
		data []byte
		mode string
	}{{"Contents/Info.plist", plist, "0644"}, {"Contents/MacOS/accessweaver", core, "0755"}, {"Contents/Resources/BUILD-INFO.json", buildData, "0644"}}
	sbom := []byte(`{"fixture":"public sealed bytes, no native installed qualification"}`)
	manifest := Manifest{SchemaVersion: 2, BundleIdentifier: BundleID, Directories: []Directory{{"Contents", "0755"}, {"Contents/MacOS", "0755"}, {"Contents/Resources", "0755"}}, PayloadSBOM: &File{Path: PayloadSBOMName, Bytes: int64(len(sbom)), SHA256: digest(sbom), Mode: "0644"}}
	for _, p := range payloads {
		manifest.Files = append(manifest.Files, File{Path: p.name, Bytes: int64(len(p.data)), SHA256: digest(p.data), Mode: p.mode})
		mode := os.FileMode(0644)
		if p.mode == "0755" {
			mode = 0755
		}
		rrWrite(t, c, filepath.Join(app, filepath.FromSlash(p.name)), p.data, mode)
	}
	encoded, e := json.Marshal(manifest)
	rrRequire(t, c, e == nil, "fixture-manifest")
	_, e = DecodeManifest(encoded)
	rrRequire(t, c, e == nil, "fixture-manifest-contract")
	rrWrite(t, c, filepath.Join(slotPath, detachedDeploymentManifest), encoded, 0644)
	rrWrite(t, c, filepath.Join(slotPath, PayloadSBOMName), sbom, 0644)
	dir := rrFile(t, c, slotPath)
	slot, e := slotFromDirectory(dir, id, deploymentIdentity{build.Version, digest(encoded), digest(core)})
	rrRequire(t, c, e == nil, "fixture-slot")
	rrRequire(t, c, dir.Close() == nil, "fixture-slot-close")
	state := deploymentState{SchemaVersion: 1, Generation: 1, HighWaterVersion: build.Version, Active: slot, Pending: []deploymentPending{}}
	record, e := encodeDeployment(state)
	rrRequire(t, c, e == nil, "fixture-record")
	rrWrite(t, c, filepath.Join(root, "state", deploymentRecord), record, 0644)
	rrWrite(t, c, filepath.Join(root, runtimeLeaseName), nil, 0644)
	parent := rrFile(t, c, base)
	held := rrFile(t, c, root)
	rrRequire(t, c, deploymentObject(held, true, 0, 0755) == nil, "fixture-real-root-protection")
	return &rrFixture{base, app, filepath.Join(app, "Contents", "MacOS", "accessweaver"), parent, held, slot, build}
}
func (f *rrFixture) verify(r runtimeReadOps, parent, root *os.File, lease *RuntimeLease) error {
	active, build, e := r.readActiveRuntime(root, f.slot.ID)
	if e != nil {
		return e
	}
	if active != f.slot {
		return errors.New("fixed unexpected fixture slot")
	}
	if e = verifyRuntimeImage(f.corePath, f.corePath, build, f.build); e != nil {
		return e
	}
	if e = r.sameDeploymentEntry(parent, deploymentRoot, root, 0); e != nil {
		return e
	}
	return r.sameRuntimeFile(root, lease.file, 0)
}
func rrLease(t *testing.T, c *runtimeReadCase, root *os.File) *RuntimeLease {
	t.Helper()
	lease, e := acquireRuntimeReader(root)
	if lease != nil {
		t.Cleanup(func() {
			if lease.Close() != nil {
				t.Error("fixture-lease-close")
			}
		})
	}
	rrRequire(t, c, e == nil && lease != nil, "fixture-real-shared-lease")
	return lease
}
func rrLive(t *testing.T, c *runtimeReadCase, file *os.File) {
	t.Helper()
	_, e := file.Stat()
	rrRequire(t, c, e == nil, "borrowed-resource-closed")
}
func rrClosed(t *testing.T, c *runtimeReadCase, counts map[*os.File]int) {
	t.Helper()
	for file, n := range counts {
		rrRequire(t, c, n == 1, "owned-close-not-once")
		_, e := file.Stat()
		rrRequire(t, c, errors.Is(e, os.ErrClosed), "owned-wrapper-retained")
	}
}
func rrMessage(e error, message string) bool {
	if e == nil {
		return false
	}
	if e.Error() == message {
		return true
	}
	if list, ok := e.(interface{ Unwrap() []error }); ok {
		for _, item := range list.Unwrap() {
			if rrMessage(item, message) {
				return true
			}
		}
	}
	if one, ok := e.(interface{ Unwrap() error }); ok {
		return rrMessage(one.Unwrap(), message)
	}
	return false
}
func rrSnapshot(t *testing.T, c *runtimeReadCase, base string) map[string]string {
	t.Helper()
	result := map[string]string{}
	e := filepath.WalkDir(base, func(path string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		st := info.Sys().(*syscall.Stat_t)
		data := []byte{}
		if info.Mode().IsRegular() {
			data, e = os.ReadFile(path)
			if e != nil {
				return e
			}
		}
		state := struct {
			Mode         os.FileMode
			Dev          int32
			Inode        uint64
			UID, GID     uint32
			Links        uint16
			Mtime, Ctime syscall.Timespec
			Hash         [32]byte
		}{info.Mode(), st.Dev, st.Ino, st.Uid, st.Gid, st.Nlink, st.Mtimespec, st.Ctimespec, sha256.Sum256(data)}
		encoded, e := json.Marshal(state)
		if e != nil {
			return e
		}
		relative, e := filepath.Rel(base, path)
		if e != nil {
			return e
		}
		result[relative] = string(encoded)
		return nil
	})
	rrRequire(t, c, e == nil, "fixture-snapshot")
	return result
}
func rrBusy(t *testing.T, c *runtimeReadCase, writer *os.File) {
	t.Helper()
	e := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if e == nil {
		_ = unix.Flock(int(writer.Fd()), unix.LOCK_UN)
	}
	rrRequire(t, c, errors.Is(e, unix.EWOULDBLOCK) || errors.Is(e, unix.EAGAIN), "lease-not-continuous")
}
func rrReleased(t *testing.T, c *runtimeReadCase, writer *os.File) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e := unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			rrRequire(t, c, unix.Flock(int(writer.Fd()), unix.LOCK_UN) == nil, "fixture-writer-unlock")
			return
		}
		rrRequire(t, c, (errors.Is(e, unix.EWOULDBLOCK) || errors.Is(e, unix.EAGAIN)) && time.Now().Before(deadline), "released-lease-retained")
		time.Sleep(time.Millisecond)
	}
}
func rrActive(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	before := rrSnapshot(t, c, f.parentPath)
	lease := rrLease(t, c, f.root)
	active, build, e := readActiveRuntime(f.root, f.slot.ID)
	rrRequire(t, c, e == nil && active == f.slot && build == f.build, "active-runtime-confirmed")
	rrLive(t, c, f.root)
	rrLive(t, c, lease.file)
	rrRequire(t, c, reflect.DeepEqual(before, rrSnapshot(t, c, f.parentPath)), "reader-mutated-fixture")
}
func rrReadCloseSites(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	lease := rrLease(t, c, f.root)
	before := rrSnapshot(t, c, f.parentPath)
	n := 0
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error { n++; return file.Close() }
	active, build, e := r.readActiveRuntime(f.root, f.slot.ID)
	rrRequire(t, c, e == nil && active == f.slot && build == f.build && n > 0 && n <= 128, "read-close-site-baseline")
	c.Sites = n
	for target := 1; target <= n; target++ {
		calls := 0
		counts := map[*os.File]int{}
		cause := errors.New("fixed read completion cofactor")
		r.closeFile = func(file *os.File) error {
			calls++
			counts[file]++
			e := file.Close()
			if calls == target {
				return errors.Join(e, cause)
			}
			return e
		}
		active, build, e = r.readActiveRuntime(f.root, f.slot.ID)
		rrRequire(t, c, errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && active == (deploymentSlot{}) && build == (buildinfo.Info{}), "unconfirmed-read-withheld")
		rrClosed(t, c, counts)
		rrLive(t, c, f.root)
		rrLive(t, c, lease.file)
	}
	rrRequire(t, c, reflect.DeepEqual(before, rrSnapshot(t, c, f.parentPath)), "reader-mutated-fixture")
}
func rrMissingCofailure(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	app := rrFile(t, c, f.appPath)
	cause := errors.New("fixed missing final directory cleanup cofactor")
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error {
		e := file.Close()
		if filepath.Base(file.Name()) == "Resources" {
			return errors.Join(e, cause)
		}
		return e
	}
	data, e := r.readPath(app, "Contents/Resources/missing.json", 16384)
	rrRequire(t, c, data == nil && errors.Is(e, unix.ENOENT) && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && !darwintrust.IsReadAbsent(e), "missing-and-cleanup-preserved")
	rrLive(t, c, app)
}
func rrBoundedCofailure(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	macos := rrFile(t, c, filepath.Dir(f.corePath))
	cause := errors.New("fixed bounded reader close cofactor")
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error { return errors.Join(file.Close(), cause) }
	data, st, e := r.readAt(macos, "accessweaver", 1)
	rrRequire(t, c, data == nil && st == (syscall.Stat_t{}) && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && rrMessage(e, "installed file exceeds read limit"), "bounded-read-and-cleanup-preserved")
	entries, e := r.deploymentEntries(f.root, 0, 1)
	rrRequire(t, c, entries == nil && errors.Is(e, cause) && rrMessage(e, "retained deployment evidence capacity exhausted; preserve and inspect"), "inventory-cap-and-cleanup-preserved")
	rrLive(t, c, macos)
}
func rrSuccessorCofailure(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	app := rrFile(t, c, f.appPath)
	a := errors.New("fixed predecessor cofactor")
	b := errors.New("fixed successor cofactor")
	counts := map[*os.File]int{}
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error {
		counts[file]++
		e := file.Close()
		if filepath.Base(file.Name()) == "Contents" {
			return errors.Join(e, a)
		}
		return errors.Join(e, b)
	}
	got, e := r.subdirectory(app, "Contents/Resources")
	rrRequire(t, c, got == nil && errors.Is(e, a) && errors.Is(e, b) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && len(counts) == 2, "path-successor-cleanup-preserved")
	rrClosed(t, c, counts)
	rrLive(t, c, app)
}
func rrSealRefusal(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	lease := rrLease(t, c, f.root)
	rrWrite(t, c, f.corePath, []byte("changed fixed fixture payload"), 0755)
	before := rrSnapshot(t, c, f.parentPath)
	cause := errors.New("fixed seal and cleanup cofactor")
	r := nativeRuntimeReads()
	counts := map[*os.File]int{}
	r.closeFile = func(file *os.File) error {
		counts[file]++
		e := file.Close()
		if filepath.Base(file.Name()) == "AccessWeaver.app" {
			return errors.Join(e, cause)
		}
		return e
	}
	active, build, e := r.readActiveRuntime(f.root, f.slot.ID)
	rrRequire(t, c, active == (deploymentSlot{}) && build == (buildinfo.Info{}) && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && rrMessage(e, "installed file differs from manifest"), "invalid-payload-remains-refused")
	rrClosed(t, c, counts)
	rrLive(t, c, lease.file)
	rrRequire(t, c, reflect.DeepEqual(before, rrSnapshot(t, c, f.parentPath)), "failed-verifier-mutated-fixture")
}
func rrScopeTransfer(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	writer := rrFile(t, c, filepath.Join(f.root.Name(), runtimeLeaseName))
	parent := rrFile(t, c, f.parentPath)
	r := nativeRuntimeReads()
	counts := map[*os.File]int{}
	r.closeFile = func(file *os.File) error { rrBusy(t, c, writer); counts[file]++; return file.Close() }
	lease, e := acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error { return f.verify(r, parent, root, lease) })
	if lease != nil {
		t.Cleanup(func() { _ = lease.Close() })
	}
	rrRequire(t, c, e == nil && lease != nil, "completed-scope-transfers-lease")
	rrClosed(t, c, counts)
	rrBusy(t, c, writer)
	rrLive(t, c, lease.file)
	rrLive(t, c, f.root)
	rrLive(t, c, f.parent)
	rrRequire(t, c, lease.Close() == nil, "caller-lease-close")
	rrReleased(t, c, writer)
}
func rrScopeCloseSites(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	writer := rrFile(t, c, filepath.Join(f.root.Name(), runtimeLeaseName))
	before := rrSnapshot(t, c, f.parentPath)
	n := 0
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error { n++; return file.Close() }
	parent := rrFile(t, c, f.parentPath)
	lease, e := acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error { return f.verify(r, parent, root, lease) })
	if lease != nil {
		t.Cleanup(func() { _ = lease.Close() })
	}
	rrRequire(t, c, e == nil && lease != nil && n > 0 && n <= 128, "scope-close-site-baseline")
	rrRequire(t, c, lease.Close() == nil, "caller-lease-close")
	rrReleased(t, c, writer)
	c.Sites = n
	for target := 1; target <= n; target++ {
		parent = rrFile(t, c, f.parentPath)
		calls := 0
		closes := 0
		entered := false
		cause := errors.New("fixed scope close cofactor")
		counts := map[*os.File]int{}
		r.closeFile = func(file *os.File) error {
			calls++
			counts[file]++
			e := file.Close()
			if calls == target {
				return errors.Join(e, cause)
			}
			return e
		}
		r.closeLease = func(lease *RuntimeLease) error { closes++; return lease.Close() }
		rejected, e := acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error {
			entered = true
			return f.verify(r, parent, root, lease)
		})
		if rejected != nil {
			t.Cleanup(func() { _ = rejected.Close() })
		}
		expectedCloses := 0
		if entered {
			expectedCloses = 1
		}
		rrRequire(t, c, rejected == nil && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && closes == expectedCloses, "failed-scope-withholds-lease")
		rrClosed(t, c, counts)
		rrReleased(t, c, writer)
		rrLive(t, c, f.root)
		rrLive(t, c, f.parent)
	}
	rrRequire(t, c, reflect.DeepEqual(before, rrSnapshot(t, c, f.parentPath)), "failed-scope-mutated-fixture")
}
func rrScopeCofailure(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	parent := rrFile(t, c, f.parentPath)
	writer := rrFile(t, c, filepath.Join(f.root.Name(), runtimeLeaseName))
	r := nativeRuntimeReads()
	var rootOwned *os.File
	var order []string
	body := errors.New("fixed body cause")
	a := errors.New("fixed root metadata cause")
	b := errors.New("fixed parent metadata cause")
	d := errors.New("fixed lease disposal cause")
	r.closeFile = func(file *os.File) error {
		e := file.Close()
		if file == rootOwned {
			order = append(order, "root")
			rrBusy(t, c, writer)
			return errors.Join(e, a)
		}
		if file == parent {
			order = append(order, "parent")
			rrBusy(t, c, writer)
			return errors.Join(e, b)
		}
		return e
	}
	r.closeLease = func(lease *RuntimeLease) error { order = append(order, "lease"); return errors.Join(lease.Close(), d) }
	lease, e := acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error {
		rootOwned = root
		if e := f.verify(r, parent, root, lease); e != nil {
			return e
		}
		return body
	})
	rrRequire(t, c, lease == nil && errors.Is(e, body) && errors.Is(e, a) && errors.Is(e, b) && errors.Is(e, d) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && reflect.DeepEqual(order, []string{"root", "parent", "lease"}), "scope-all-causes-and-order")
	rrReleased(t, c, writer)
	rrLive(t, c, f.root)
}
func rrScopeBlocked(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	parent := rrFile(t, c, f.parentPath)
	writer := rrFile(t, c, filepath.Join(f.root.Name(), runtimeLeaseName))
	r := nativeRuntimeReads()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cause := errors.New("fixed blocked metadata close cause")
	r.closeFile = func(file *os.File) error {
		if file == parent {
			close(entered)
			<-release
			return errors.Join(file.Close(), cause)
		}
		return file.Close()
	}
	type result struct {
		lease *RuntimeLease
		err   error
	}
	done := make(chan result, 1)
	go func() {
		lease, e := acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error { return f.verify(r, parent, root, lease) })
		done <- result{lease, e}
	}()
	joined := false
	defer func() {
		unblock()
		if !joined {
			select {
			case out := <-done:
				if out.lease != nil {
					_ = out.lease.Close()
				}
			case <-time.After(5 * time.Second):
				t.Error("scope-worker-not-joined")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		rrRequire(t, c, false, "metadata-close-not-entered")
	}
	rrBusy(t, c, writer)
	select {
	case out := <-done:
		joined = true
		if out.lease != nil {
			_ = out.lease.Close()
		}
		rrRequire(t, c, false, "scope-returned-before-close")
	default:
	}
	unblock()
	select {
	case out := <-done:
		joined = true
		rrRequire(t, c, out.lease == nil && errors.Is(out.err, cause) && errors.Is(out.err, darwintrust.ErrReadCleanupUncertain), "blocked-scope-final-outcome")
	case <-time.After(5 * time.Second):
		rrRequire(t, c, false, "scope-worker-not-joined")
	}
	rrReleased(t, c, writer)
	rrLive(t, c, f.root)
}
func rrScopePanic(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	parent := rrFile(t, c, f.parentPath)
	writer := rrFile(t, c, filepath.Join(f.root.Name(), runtimeLeaseName))
	r := nativeRuntimeReads()
	closed := 0
	r.closeLease = func(lease *RuntimeLease) error { closed++; return lease.Close() }
	token := &struct{}{}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_, _ = acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error {
			if e := f.verify(r, parent, root, lease); e != nil {
				return e
			}
			panic(token)
		})
	}()
	rrRequire(t, c, recovered == token && closed == 1, "original-panic-and-lease-cleanup")
	rrReleased(t, c, writer)
	rrLive(t, c, f.root)
}
func rrRaw(t *testing.T, c *runtimeReadCase, f *rrFixture, name string) (int, *bool) {
	t.Helper()
	fd, e := unix.Openat(int(f.root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	rrRequire(t, c, e == nil && fd >= 3 && fd <= 1024, "fixture-raw-descriptor")
	owned := true
	t.Cleanup(func() {
		if owned && unix.Close(fd) != nil {
			t.Error("fixture-raw-close")
		}
	})
	return fd, &owned
}
func rrInheritedTransfer(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	fd, rawOwned := rrRaw(t, c, f, runtimeLeaseName)
	rrRequire(t, c, unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB) == nil, "fixture-inherited-lease")
	t.Setenv(runtimeLeaseEnvironment, strconv.Itoa(fd))
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error {
		if int(file.Fd()) == fd {
			*rawOwned = false
		}
		return file.Close()
	}
	lease, e := r.acquireRuntimeReader(f.root)
	if lease != nil {
		*rawOwned = false
		t.Cleanup(func() { _ = lease.Close() })
	}
	rrRequire(t, c, e == nil && lease != nil && int(lease.file.Fd()) == fd, "inherited-lease-adopted")
	_, present := os.LookupEnv(runtimeLeaseEnvironment)
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	rrRequire(t, c, !present && e == nil && flags&unix.FD_CLOEXEC != 0, "inherited-hint-cleared-and-cloexec")
	writer := rrFile(t, c, filepath.Join(f.root.Name(), runtimeLeaseName))
	rrBusy(t, c, writer)
	rrRequire(t, c, lease.Close() == nil, "caller-lease-close")
	rrReleased(t, c, writer)
}
func rrInheritedCofailure(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	fd, rawOwned := rrRaw(t, c, f, runtimeLeaseName)
	rrRequire(t, c, unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB) == nil, "fixture-inherited-lease")
	t.Setenv(runtimeLeaseEnvironment, strconv.Itoa(fd))
	r := nativeRuntimeReads()
	a := errors.New("fixed lookup close cause")
	b := errors.New("fixed adopted close cause")
	calls := 0
	r.closeFile = func(file *os.File) error {
		calls++
		inherited := int(file.Fd()) == fd
		if inherited {
			*rawOwned = false
		}
		e := file.Close()
		if inherited {
			return errors.Join(e, b)
		}
		return errors.Join(e, a)
	}
	lease, e := r.acquireRuntimeReader(f.root)
	rrRequire(t, c, lease == nil && errors.Is(e, a) && errors.Is(e, b) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && calls == 2 && !*rawOwned, "lookup-and-adopted-close-causes")
	_, check := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	rrRequire(t, c, errors.Is(check, unix.EBADF), "adopted-descriptor-retained")
	writer := rrFile(t, c, filepath.Join(f.root.Name(), runtimeLeaseName))
	rrReleased(t, c, writer)
}
func rrForeignDescriptor(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	rrWrite(t, c, filepath.Join(f.root.Name(), "foreign"), nil, 0644)
	fd, _ := rrRaw(t, c, f, "foreign")
	t.Setenv(runtimeLeaseEnvironment, strconv.Itoa(fd))
	cause := errors.New("fixed foreign refusal lookup close cause")
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error { return errors.Join(file.Close(), cause) }
	lease, e := r.acquireRuntimeReader(f.root)
	_, still := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	rrRequire(t, c, lease == nil && errors.Is(e, cause) && rrMessage(e, "inherited runtime descriptor identity differs") && still == nil, "foreign-descriptor-never-adopted-or-closed")
}
func rrParseAndBusy(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	r := nativeRuntimeReads()
	cause := errors.New("fixed refused acquisition cleanup cause")
	r.closeFile = func(file *os.File) error { return errors.Join(file.Close(), cause) }
	t.Setenv(runtimeLeaseEnvironment, "-1")
	lease, e := r.acquireRuntimeReader(f.root)
	rrRequire(t, c, lease == nil && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && rrMessage(e, "invalid inherited runtime descriptor"), "parse-refusal-retains-close")
	rrRequire(t, c, os.Unsetenv(runtimeLeaseEnvironment) == nil, "fixture-hint-clear")
	writer := rrFile(t, c, filepath.Join(f.root.Name(), runtimeLeaseName))
	rrRequire(t, c, unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil, "fixture-exclusive-writer")
	lease, e = r.acquireRuntimeReader(f.root)
	rrRequire(t, c, lease == nil && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && (errors.Is(e, unix.EWOULDBLOCK) || errors.Is(e, unix.EAGAIN)), "busy-refusal-retains-close")
	rrLive(t, c, writer)
	rrRequire(t, c, unix.Flock(int(writer.Fd()), unix.LOCK_UN) == nil, "fixture-writer-unlock")
}
func rrAuthorityAndIdentity(t *testing.T, c *runtimeReadCase) {
	f := rrNew(t, c)
	rrRequire(t, c, LaunchInstalled([]string{"ui"}) != nil, "root-launcher-stays-refused")
	other := filepath.Join(f.parentPath, "other")
	rrWrite(t, c, other, []byte("fixed unrelated file"), 0644)
	rrRequire(t, c, verifyRuntimeImage(f.corePath, other, f.build, f.build) != nil, "different-image-refused")
	changed := f.build
	changed.Version = "0.2.0"
	rrRequire(t, c, verifyRuntimeImage(f.corePath, f.corePath, f.build, changed) != nil, "different-build-refused")
	cause := errors.New("fixed rejected metadata cleanup cause")
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error { return errors.Join(file.Close(), cause) }
	versions := rrFile(t, c, filepath.Join(f.root.Name(), "versions"))
	bad := f.slot
	bad.Inode++
	dir, e := r.openSlot(&deploymentStore{owner: 0, versions: versions}, bad)
	rrRequire(t, c, dir == nil && errors.Is(e, cause) && rrMessage(e, "reserved deployment slot identity changed"), "changed-slot-and-close-refused")
	rrRequire(t, c, os.Chmod(f.root.Name(), 0700) == nil, "fixture-root-mode")
	defer func() {
		if os.Chmod(f.root.Name(), 0755) != nil {
			t.Error("fixture-root-mode-restore")
		}
	}()
	dir, e = r.deploymentDirectory(f.parent, deploymentRoot, 0, false)
	rrRequire(t, c, dir == nil && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && rrMessage(e, "deployment object mode differs"), "wrong-mode-and-close-refused")
	rrLive(t, c, f.root)
	rrLive(t, c, f.parent)
}

// The only retained data is source-bound fixed case/code labels and counts.
// This explicitly does not qualify installed or signed production packages.
func rrReport(cases []runtimeReadCase) bool {
	commit := os.Getenv("GITHUB_SHA")
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return false
	}
	outcome := "passed"
	for _, c := range cases {
		if !c.Passed {
			outcome = "failed"
		}
	}
	// The root fixture writes only a bounded fixed-schema protocol to its pipe.
	// Source binding and artifact publication belong to the ordinary runner.
	report := struct {
		SchemaVersion            int               `json:"schemaVersion"`
		SourceCommit             string            `json:"sourceCommit"`
		GOOS                     string            `json:"goos"`
		GOARCH                   string            `json:"goarch"`
		GoVersion                string            `json:"goVersion"`
		Outcome                  string            `json:"outcome"`
		Cases                    []runtimeReadCase `json:"cases"`
		NativeRootFixture        bool              `json:"nativeRootFixture"`
		NativeInstalledQualified bool              `json:"nativeInstalledQualified"`
	}{1, commit, runtime.GOOS, runtime.GOARCH, runtime.Version(), outcome, cases, true, false}
	data, e := json.Marshal(report)
	if e != nil || len(data) > 16384 {
		return false
	}
	line := "RUNTIME-READ-RESULT " + string(data) + "\n"
	n, written := io.WriteString(os.Stdout, line)
	return n == len(line) && written == nil
}
