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
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// No installed app or caller-selected system path enters this suite. The
// existing sealed read fixture supplies inert source bytes; every mutation is
// confined to a separately created root-owned temporary deployment store.
func TestDarwinDeploymentCompletionContracts(t *testing.T) {
	if os.Getenv("ACCESSWEAVER_DISPOSABLE_DARWIN_DEPLOYMENT_COMPLETION_TEST") != "1" {
		t.Skip("requires opted-in hosted root deployment completion fixture")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "macOS" {
		t.Fatal("native-deployment-completion-guard")
	}
	var results []runtimeReadCase
	cases := []struct {
		name string
		run  func(*testing.T, *runtimeReadCase)
	}{
		{"prepare-close-sites", dcPrepareCloseSites},
		{"payload-close-sites", dcPayloadCloseSites},
		{"partial-copy-preserved", dcPartialCopy},
		{"complete-copy-reconcile", dcCompleteCopyReconcile},
		{"source-postpublication", dcSourcePostpublication},
		{"record-postpublication", dcRecordPostpublication},
		{"phase-postpublication", dcPhasePostpublication},
		{"partial-source-owner", dcPartialSourceOwner},
		{"store-close-sites", dcStoreCloseSites},
		{"store-lock-lifetime", dcStoreLockLifetime},
		{"store-multiple-causes", dcStoreMultipleCauses},
		{"creation-cofailure", dcCreationCofailure},
		{"idempotent-activation", dcIdempotentActivation},
		{"reconcile-publication", dcReconcilePublication},
		{"source-factory", dcSourceFactory},
		{"input-preflight", dcInputPreflight},
	}
	for _, item := range cases {
		c := runtimeReadCase{Name: item.name, Code: "none"}
		c.Passed = t.Run(item.name, func(t *testing.T) { item.run(t, &c) })
		results = append(results, c)
	}
	if !dcReport(results) {
		t.Error("deployment-completion-report")
	}
}

type dcOwnedStore struct {
	s             *deploymentStore
	expectedClose error
	path          string
}

func dcStore(t *testing.T, c *runtimeReadCase) *dcOwnedStore {
	t.Helper()
	path := t.TempDir()
	parent, e := os.Open(path)
	rrRequire(t, c, e == nil, "fixture-store-parent")
	s, e := beginDeployment(parent, 0, nil)
	rrRequire(t, c, e == nil && s != nil, "fixture-real-deployment-store")
	own := &dcOwnedStore{s: s, path: path}
	t.Cleanup(func() {
		e := s.Close()
		if e != own.expectedClose {
			t.Error("fixture-unexpected-store-close")
		}
	})
	return own
}

type dcInput struct {
	fixture         *rrFixture
	container, app  *os.File
	inventory, sbom []byte
	embedded        bool
}

func dcSource(t *testing.T, c *runtimeReadCase) *dcInput {
	t.Helper()
	f := rrNew(t, c)
	container := rrFile(t, c, filepath.Dir(f.appPath))
	app, inventory, sbom, embedded, e := openDeploymentBundle(container)
	rrRequire(t, c, e == nil && app != nil && !embedded && len(sbom) > 0, "fixture-sealed-source")
	t.Cleanup(func() {
		if e := app.Close(); e != nil && !errors.Is(e, os.ErrClosed) {
			t.Error("fixture-source-close")
		}
	})
	return &dcInput{f, container, app, inventory, sbom, embedded}
}
func dcPrepared(t *testing.T, c *runtimeReadCase, own *dcOwnedStore, src *dcInput) deploymentSlot {
	t.Helper()
	slot, e := own.s.prepare(src.fixture.slot.Identity)
	rrRequire(t, c, e == nil && slot.ID != "" && len(own.s.state.Pending) == 1, "fixture-prepared-slot")
	return slot
}
func dcCopy(d deploymentCompletion, s *deploymentStore, slot deploymentSlot, src *dcInput) (bool, error) {
	return d.copyBundleAndActivate(s, slot, src.app, src.inventory, src.embedded, src.sbom)
}
func dcActive(t *testing.T, c *runtimeReadCase, s *deploymentStore, slot deploymentSlot) {
	t.Helper()
	rrRequire(t, c, s.state.Active == slot && s.state.Generation == 1 && len(s.state.Pending) == 0, "published-state-confirmed")
	data, e := s.readRecord(s.current)
	rrRequire(t, c, e == nil && bytes.Equal(data, s.encoded), "published-record-confirmed")
	rrRequire(t, c, s.verifySlot(slot) == nil, "published-payload-confirmed")
}
func dcOpenAgain(t *testing.T, c *runtimeReadCase, own *dcOwnedStore) *deploymentStore {
	t.Helper()
	rrRequire(t, c, own.s.Close() == nil, "fixture-store-finish")
	parent, e := os.Open(own.path)
	rrRequire(t, c, e == nil, "fixture-store-reopen-parent")
	s, e := beginDeployment(parent, 0, nil)
	rrRequire(t, c, e == nil && s != nil, "fixture-store-reopen")
	t.Cleanup(func() {
		if s.Close() != nil {
			t.Error("fixture-reopened-store-close")
		}
	})
	return s
}
func dcPrepareCloseSites(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	baseline := dcStore(t, c)
	d := nativeDeploymentCompletion()
	n := 0
	d.closeFile = func(file *os.File) error { n++; return file.Close() }
	_, published, _, e := d.reconcileDeployment(baseline.s, "prepare-deployment", src.fixture.slot.Identity, nil)
	rrRequire(t, c, e == nil && published && n > 0 && n <= 128, "prepare-close-baseline")
	c.Sites = n
	for target := 1; target <= n; target++ {
		own := dcStore(t, c)
		before := append([]byte{}, own.s.encoded...)
		cause := errors.New("fixed prepare cleanup cofactor")
		calls := 0
		counts := map[*os.File]int{}
		d.closeFile = func(file *os.File) error {
			calls++
			counts[file]++
			e := file.Close()
			if calls == target {
				return errors.Join(e, cause)
			}
			return e
		}
		slot, published, _, e := d.reconcileDeployment(own.s, "prepare-deployment", src.fixture.slot.Identity, nil)
		changed := !bytes.Equal(before, own.s.encoded)
		rrRequire(t, c, errors.Is(e, cause) && errors.Is(e, ErrDeploymentCleanupUncertain) && published == changed && slot.ID != "", "prepare-publication-truth")
		rrClosed(t, c, counts)
		reopened := dcOpenAgain(t, c, own)
		rrRequire(t, c, len(reopened.state.Pending) == boolInt(changed) && reopened.state.Active == (deploymentSlot{}), "prepare-reopen-truth")
	}
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func dcPayloadCloseSites(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	sourceBefore := rrSnapshot(t, c, src.fixture.parentPath)
	base := dcStore(t, c)
	slot := dcPrepared(t, c, base, src)
	n := 0
	d := nativeDeploymentCompletion()
	d.closeFile = func(file *os.File) error { n++; return file.Close() }
	published, e := dcCopy(d, base.s, slot, src)
	rrRequire(t, c, e == nil && published && n > 0 && n <= 128, "payload-close-baseline")
	c.Sites = n
	for target := 1; target <= n; target++ {
		own := dcStore(t, c)
		slot := dcPrepared(t, c, own, src)
		before := append([]byte{}, own.s.encoded...)
		cause := errors.New("fixed payload cleanup cofactor")
		calls := 0
		counts := map[*os.File]int{}
		d.closeFile = func(file *os.File) error {
			calls++
			counts[file]++
			e := file.Close()
			if calls == target {
				return errors.Join(e, cause)
			}
			return e
		}
		published, e := dcCopy(d, own.s, slot, src)
		changed := !bytes.Equal(before, own.s.encoded)
		rrRequire(t, c, errors.Is(e, cause) && errors.Is(e, ErrDeploymentCleanupUncertain) && published == changed, "payload-publication-truth")
		rrClosed(t, c, counts)
		rrLive(t, c, src.app)
		reopened := dcOpenAgain(t, c, own)
		rrRequire(t, c, (reopened.state.Active == slot) == changed, "payload-reopen-truth")
	}
	rrRequire(t, c, reflect.DeepEqual(sourceBefore, rrSnapshot(t, c, src.fixture.parentPath)), "copy-mutated-source")
}
func dcPartialCopy(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	slot := dcPrepared(t, c, own, src)
	before := append([]byte{}, own.s.encoded...)
	cause := errors.New("fixed partial directory cleanup cofactor")
	d := nativeDeploymentCompletion()
	targetRoot := filepath.Join(own.s.versions.Name(), slot.ID)
	d.closeFile = func(file *os.File) error {
		e := file.Close()
		if file.Name() == filepath.Join(targetRoot, "AccessWeaver.app", "Contents") {
			return errors.Join(e, cause)
		}
		return e
	}
	published, e := dcCopy(d, own.s, slot, src)
	rrRequire(t, c, !published && errors.Is(e, cause) && bytes.Equal(before, own.s.encoded), "partial-copy-not-published")
	retained := rrSnapshot(t, c, targetRoot)
	reopened := dcOpenAgain(t, c, own)
	opened := 0
	_, published, _, e = reopened.reconcileDeployment("activate-deployment", src.fixture.slot.Identity, func() (*os.File, error) { opened++; return nil, errors.New("fixed unexpected source request") })
	rrRequire(t, c, e != nil && !published && opened == 0 && reopened.state.Active == (deploymentSlot{}) && reflect.DeepEqual(retained, rrSnapshot(t, c, targetRoot)), "partial-copy-preserved-on-reconcile")
}
func dcCompleteCopyReconcile(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	slot := dcPrepared(t, c, own, src)
	cause := errors.New("fixed completed payload metadata cleanup cofactor")
	d := nativeDeploymentCompletion()
	targetRoot := filepath.Join(own.s.versions.Name(), slot.ID)
	d.closeFile = func(file *os.File) error {
		e := file.Close()
		if file.Name() == filepath.Join(targetRoot, "AccessWeaver.app") {
			return errors.Join(e, cause)
		}
		return e
	}
	published, e := dcCopy(d, own.s, slot, src)
	rrRequire(t, c, !published && errors.Is(e, cause) && own.s.state.Active == (deploymentSlot{}) && own.s.verifySlot(slot) == nil, "complete-copy-awaits-confirmed-cleanup")
	retained := rrSnapshot(t, c, targetRoot)
	reopened := dcOpenAgain(t, c, own)
	opened := 0
	_, published, state, e := reopened.reconcileDeployment("activate-deployment", src.fixture.slot.Identity, func() (*os.File, error) { opened++; return nil, errors.New("fixed unexpected source request") })
	rrRequire(t, c, e == nil && published && state == "active" && opened == 0 && reflect.DeepEqual(retained, rrSnapshot(t, c, targetRoot)), "complete-copy-reconciles-without-recopy")
	dcActive(t, c, reopened, slot)
}
func dcSourcePostpublication(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	slot := dcPrepared(t, c, own, src)
	cause := errors.New("fixed source app cleanup after publication")
	d := nativeDeploymentCompletion()
	closed := 0
	d.closeFile = func(file *os.File) error {
		e := file.Close()
		if file.Name() == src.fixture.appPath {
			closed++
			return errors.Join(e, cause)
		}
		return e
	}
	published, e := d.copyIncomingAndActivate(own.s, slot, src.container)
	rrRequire(t, c, published && errors.Is(e, cause) && errors.Is(e, ErrDeploymentCleanupUncertain) && closed == 1, "late-source-cleanup-retains-publication")
	rrLive(t, c, src.container)
	rrLive(t, c, src.app)
	dcActive(t, c, own.s, slot)
	dcActive(t, c, dcOpenAgain(t, c, own), slot)
}
func dcRecordPostpublication(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	slot := dcPrepared(t, c, own, src)
	old := own.s.current
	cause := errors.New("fixed old record cleanup after publication")
	d := nativeDeploymentCompletion()
	d.closeFile = func(file *os.File) error {
		e := file.Close()
		if file == old {
			return errors.Join(e, cause)
		}
		return e
	}
	published, e := dcCopy(d, own.s, slot, src)
	rrRequire(t, c, published && errors.Is(e, cause) && errors.Is(e, ErrDeploymentCleanupUncertain), "old-record-cleanup-retains-publication")
	dcActive(t, c, own.s, slot)
	dcActive(t, c, dcOpenAgain(t, c, own), slot)
}
func dcPhasePostpublication(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	slot := dcPrepared(t, c, own, src)
	body := errors.New("fixed postpublication phase cause")
	cleanup := errors.New("fixed source cleanup phase cofailure")
	d := nativeDeploymentCompletion()
	own.s.observe = func(phase string) error {
		if phase == "record-published" {
			return body
		}
		return nil
	}
	d.closeFile = func(file *os.File) error {
		e := file.Close()
		if file.Name() == src.fixture.appPath {
			return errors.Join(e, cleanup)
		}
		return e
	}
	published, e := d.copyIncomingAndActivate(own.s, slot, src.container)
	rrRequire(t, c, published && errors.Is(e, body) && errors.Is(e, cleanup) && errors.Is(e, ErrDeploymentCleanupUncertain), "phase-and-cleanup-retain-publication")
	dcActive(t, c, own.s, slot)
	own.s.observe = nil
	dcActive(t, c, dcOpenAgain(t, c, own), slot)
}
func dcPartialSourceOwner(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	_ = dcPrepared(t, c, own, src)
	before := append([]byte{}, own.s.encoded...)
	file := rrFile(t, c, src.container.Name())
	body := errors.New("fixed partial source factory cause")
	closed := errors.New("fixed partial source close cause")
	d := nativeDeploymentCompletion()
	calls := 0
	d.closeFile = func(owned *os.File) error {
		e := owned.Close()
		if owned == file {
			calls++
			return errors.Join(e, closed)
		}
		return e
	}
	_, published, _, e := d.reconcileDeployment(own.s, "activate-deployment", src.fixture.slot.Identity, func() (*os.File, error) { return file, body })
	rrRequire(t, c, !published && errors.Is(e, body) && errors.Is(e, closed) && calls == 1 && bytes.Equal(before, own.s.encoded), "partial-source-owner-cleaned")
	rrClosed(t, c, map[*os.File]int{file: calls})
	rrLive(t, c, src.container)
}
func dcStoreCloseSites(t *testing.T, c *runtimeReadCase) {
	for target := 1; target <= 6; target++ {
		own := dcStore(t, c)
		cause := errors.New("fixed cached store close cause")
		calls := 0
		counts := map[*os.File]int{}
		d := nativeDeploymentCompletion()
		d.closeFile = func(file *os.File) error {
			calls++
			counts[file]++
			e := file.Close()
			if calls == target {
				return errors.Join(e, cause)
			}
			return e
		}
		e := own.s.closeWith(d)
		own.expectedClose = e
		rrRequire(t, c, errors.Is(e, cause) && errors.Is(e, ErrDeploymentCleanupUncertain) && calls == 6, "store-close-error-retained")
		rrRequire(t, c, own.s.Close() == e && own.s.closeWith(d) == e && calls == 6, "store-close-cached-not-retried")
		rrClosed(t, c, counts)
	}
	c.Sites = 6
}
func dcStoreLockLifetime(t *testing.T, c *runtimeReadCase) {
	own := dcStore(t, c)
	parent := own.s.parent
	runtimeLock := rrFile(t, c, filepath.Join(own.path, deploymentRoot, runtimeLeaseName))
	deploymentLockFile := rrFile(t, c, filepath.Join(own.path, deploymentRoot, deploymentLock))
	d := nativeDeploymentCompletion()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	cause := errors.New("fixed blocked store metadata close cause")
	d.closeFile = func(file *os.File) error {
		if file == parent {
			close(entered)
			<-release
			return errors.Join(file.Close(), cause)
		}
		return file.Close()
	}
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- own.s.closeWith(d) }()
	joinedFirst, joinedSecond := false, false
	defer func() {
		unblock()
		if !joinedFirst {
			select {
			case own.expectedClose = <-first:
			case <-time.After(5 * time.Second):
				t.Error("store-first-close-not-joined")
			}
		}
		if !joinedSecond {
			select {
			case <-second:
			case <-time.After(5 * time.Second):
				t.Error("store-second-close-not-joined")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		rrRequire(t, c, false, "store-close-boundary-not-entered")
	}
	go func() { second <- own.s.Close() }()
	rrBusy(t, c, runtimeLock)
	rrBusy(t, c, deploymentLockFile)
	select {
	case <-first:
		joinedFirst = true
		rrRequire(t, c, false, "store-close-returned-early")
	default:
	}
	select {
	case <-second:
		joinedSecond = true
		rrRequire(t, c, false, "concurrent-store-close-returned-early")
	default:
	}
	unblock()
	var e error
	select {
	case e = <-first:
		joinedFirst = true
		own.expectedClose = e
	case <-time.After(5 * time.Second):
		rrRequire(t, c, false, "store-first-close-not-joined")
	}
	select {
	case cached := <-second:
		joinedSecond = true
		rrRequire(t, c, cached == e && errors.Is(e, cause), "concurrent-store-close-cache")
	case <-time.After(5 * time.Second):
		rrRequire(t, c, false, "store-second-close-not-joined")
	}
	rrReleased(t, c, runtimeLock)
	rrReleased(t, c, deploymentLockFile)
}
func dcStoreMultipleCauses(t *testing.T, c *runtimeReadCase) {
	own := dcStore(t, c)
	var causes []error
	d := nativeDeploymentCompletion()
	calls := 0
	d.closeFile = func(file *os.File) error {
		calls++
		cause := errors.New("fixed individual store cleanup cause")
		causes = append(causes, cause)
		return errors.Join(file.Close(), cause)
	}
	e := own.s.closeWith(d)
	own.expectedClose = e
	rrRequire(t, c, calls == 6 && errors.Is(e, ErrDeploymentCleanupUncertain), "all-store-cleanups-attempted")
	for _, cause := range causes {
		rrRequire(t, c, errors.Is(e, cause), "individual-store-cause-preserved")
	}
	rrRequire(t, c, own.s.Close() == e && calls == 6, "all-store-causes-cached")
}
func dcCreationCofailure(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	slot := dcPrepared(t, c, own, src)
	target := filepath.Join(own.s.versions.Name(), slot.ID, "AccessWeaver.app", "Contents", "Info.plist")
	parent := filepath.Dir(target)
	fixed := []byte("fixed preexisting fixture evidence")
	created := false
	own.s.observe = func(phase string) error {
		if phase == "payload-manifest-durable" {
			e := os.WriteFile(target, fixed, 0644)
			created = e == nil
			return e
		}
		return nil
	}
	cause := errors.New("fixed failed creation parent close cofactor")
	d := nativeDeploymentCompletion()
	d.closeFile = func(file *os.File) error {
		e := file.Close()
		if created && file.Name() == parent {
			return errors.Join(e, cause)
		}
		return e
	}
	published, e := dcCopy(d, own.s, slot, src)
	data, read := os.ReadFile(target)
	rrRequire(t, c, created && !published && errors.Is(e, unix.EEXIST) && errors.Is(e, cause) && errors.Is(e, ErrDeploymentCleanupUncertain) && read == nil && bytes.Equal(data, fixed), "creation-and-parent-cleanup-preserve-evidence")
}
func dcIdempotentActivation(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	slot := dcPrepared(t, c, own, src)
	published, e := dcCopy(nativeDeploymentCompletion(), own.s, slot, src)
	rrRequire(t, c, e == nil && published, "fixture-copy-activated")
	before := append([]byte{}, own.s.encoded...)
	sourceCalls := 0
	returned, published, state, e := own.s.reconcileDeployment("activate-deployment", src.fixture.slot.Identity, func() (*os.File, error) { sourceCalls++; return nil, errors.New("fixed unexpected source read") })
	rrRequire(t, c, e == nil && !published && state == "active" && returned == slot && sourceCalls == 0 && bytes.Equal(before, own.s.encoded), "idempotent-activation-not-republished")
}
func dcReconcilePublication(t *testing.T, c *runtimeReadCase) {
	src := dcSource(t, c)
	own := dcStore(t, c)
	slot := dcPrepared(t, c, own, src)
	container := rrFile(t, c, src.container.Name())
	a := errors.New("fixed source app cleanup cause")
	b := errors.New("fixed source container cleanup cause")
	d := nativeDeploymentCompletion()
	d.closeFile = func(file *os.File) error {
		e := file.Close()
		if file == container {
			return errors.Join(e, b)
		}
		if file.Name() == src.fixture.appPath {
			return errors.Join(e, a)
		}
		return e
	}
	returned, published, state, e := d.reconcileDeployment(own.s, "activate-deployment", src.fixture.slot.Identity, func() (*os.File, error) { return container, nil })
	rrRequire(t, c, returned == slot && published && state == "active" && errors.Is(e, a) && errors.Is(e, b) && errors.Is(e, ErrDeploymentCleanupUncertain), "reconcile-preserves-published-error-outcome")
	dcActive(t, c, own.s, slot)
}
func dcIncoming(t *testing.T, c *runtimeReadCase) (string, deploymentIdentity) {
	t.Helper()
	parent := t.TempDir()
	incoming := filepath.Join(parent, deploymentIncoming)
	rrRequire(t, c, os.Mkdir(incoming, 0755) == nil, "fixture-incoming-directory")
	rrRequire(t, c, os.Chmod(incoming, 0755) == nil, "fixture-incoming-mode")
	identity := deploymentIdentity{Version: "0.1.0-alpha", ManifestSHA256: stringsRepeatA(), PayloadSHA256: stringsRepeatA()}
	return parent, identity
}
func stringsRepeatA() string {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
func dcSourceFactory(t *testing.T, c *runtimeReadCase) {
	path, identity := dcIncoming(t, c)
	rrRequire(t, c, os.Mkdir(filepath.Join(path, deploymentIncoming, identity.ManifestSHA256), 0755) == nil, "fixture-incoming-stage")
	parent := rrFile(t, c, path)
	cause := errors.New("fixed source factory metadata cleanup cause")
	r := nativeRuntimeReads()
	counts := map[*os.File]int{}
	r.closeFile = func(file *os.File) error { counts[file]++; return errors.Join(file.Close(), cause) }
	source, e := openDeploymentIncomingAt(parent, identity, r)
	rrRequire(t, c, source == nil && errors.Is(e, cause) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && len(counts) == 3, "source-factory-withholds-unconfirmed-owner")
	rrClosed(t, c, counts)
}
func dcInputPreflight(t *testing.T, c *runtimeReadCase) {
	path, identity := dcIncoming(t, c)
	parent := rrFile(t, c, path)
	cause := errors.New("fixed absent input metadata close cause")
	r := nativeRuntimeReads()
	r.closeFile = func(file *os.File) error { return errors.Join(file.Close(), cause) }
	e := packageIncomingAt(parent, identity, false, r)
	rrRequire(t, c, errors.Is(e, cause) && errors.Is(e, unix.ENOENT) && errors.Is(e, darwintrust.ErrReadCleanupUncertain) && !darwintrust.IsReadAbsent(e), "absent-input-needs-confirmed-cleanup")
	parent = rrFile(t, c, path)
	rrRequire(t, c, packageIncomingAt(parent, identity, false, nativeRuntimeReads()) == nil, "confirmed-absent-input-remains-allowed")
}
func dcReport(cases []runtimeReadCase) bool {
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
	line := "DEPLOYMENT-COMPLETION-RESULT " + string(data) + "\n"
	n, written := io.WriteString(os.Stdout, line)
	return n == len(line) && written == nil
}
