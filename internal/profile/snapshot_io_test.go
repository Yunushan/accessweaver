package profile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
)

type snapshotIOFixture struct {
	root     string
	preserve atomic.Bool
}

func newSnapshotIOFixture(t *testing.T) *snapshotIOFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-snapshot-io-")
	if err != nil {
		t.Fatal("owned snapshot fixture unavailable")
	}
	state, err := fileinput.StateFromPath(root, false)
	if err != nil {
		t.Fatal("owned snapshot fixture identity unavailable")
	}
	f := &snapshotIOFixture{root: root}
	t.Cleanup(func() {
		if f.preserve.Load() {
			t.Error("unconfirmed snapshot fixture retained")
			return
		}
		current, err := fileinput.StateFromPath(root, false)
		if err != nil || current.ID != state.ID || current.Kind != state.Kind {
			t.Error("changed snapshot fixture retained")
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("owned snapshot fixture cleanup failed")
		}
	})
	return f
}
func (f *snapshotIOFixture) store(t *testing.T) *Store {
	t.Helper()
	s, err := NewStoreWithGuard(filepath.Join(f.root, "source"), managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(snapshotFixture()[0]); err != nil {
		t.Fatal(err)
	}
	return s
}
func snapshotObservedOps(t *testing.T, f *snapshotIOFixture) (snapshotIO, map[io.Closer]string, map[string]int) {
	ops := physicalSnapshotIO()
	originalAcquire, originalClose := ops.acquire, ops.close
	names := map[io.Closer]string{}
	closed := map[string]int{}
	ops.acquire = func(ctx context.Context, path string, immediate bool) (io.Closer, error) {
		owned, err := originalAcquire(ctx, path, immediate)
		if err == nil {
			names[owned] = filepath.Base(path)
		}
		return owned, err
	}
	ops.close = func(owned io.Closer) error {
		name := names[owned]
		if file, ok := owned.(*os.File); ok {
			name = "directory:" + filepath.Base(file.Name())
		}
		closed[name]++
		err := originalClose(owned)
		if err != nil {
			f.preserve.Store(true)
			t.Error("actual snapshot fixture close failed before injection")
		}
		return err
	}
	return ops, names, closed
}
func TestSnapshotIOCloseFailureWithholdsProfilesAndReleasesActualOwnersOnce(t *testing.T) {
	for _, target := range []string{"directory:profiles", ".profiles.lock"} {
		t.Run(target, func(t *testing.T) {
			f := newSnapshotIOFixture(t)
			store := f.store(t)
			before, err := os.ReadFile(filepath.Join(store.Root, "profiles", snapshotFixture()[0].ID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			ops, names, closed := snapshotObservedOps(t, f)
			originalClose := ops.close
			fault := errors.New("injected owned close cofailure")
			ops.close = func(owned io.Closer) error {
				err := originalClose(owned)
				name := names[owned]
				if file, ok := owned.(*os.File); ok {
					name = "directory:" + filepath.Base(file.Name())
				}
				if name == target {
					return snapshotJoin(err, fault)
				}
				return err
			}
			profiles, err := snapshotContext(context.Background(), store, ops)
			if profiles != nil || !errors.Is(err, fault) {
				t.Fatal("unconfirmed close adopted a snapshot", err)
			}
			if closed["directory:profiles"] != 1 || closed[".profiles.lock"] != 1 {
				t.Fatal("owned closes were not attempted exactly once", closed)
			}
			after, err := os.ReadFile(filepath.Join(store.Root, "profiles", snapshotFixture()[0].ID+".json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("read failure changed profiles")
			}
			lease, err := filelock.TryAcquire(filepath.Join(store.Root, ".profiles.lock"))
			if err != nil {
				f.preserve.Store(true)
				t.Fatal("actual profile owner was not released")
			}
			if err := lease.Close(); err != nil {
				f.preserve.Store(true)
				t.Fatal("lock probe close unconfirmed")
			}
		})
	}
}
func TestSnapshotIOReadCancelAndBothCloseCofailuresSurviveWithoutAdoption(t *testing.T) {
	f := newSnapshotIOFixture(t)
	store := f.store(t)
	ops, _, closed := snapshotObservedOps(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readFault, closeFault := errors.New("injected directory read cofailure"), errors.New("injected close cofailure")
	readDir, closeOwned := ops.readDirectory, ops.close
	reads := 0
	ops.readDirectory = func(file *os.File, n int) ([]os.DirEntry, error) {
		entries, err := readDir(file, n)
		if err != nil && err != io.EOF {
			return entries, err
		}
		cancel()
		return entries, readFault
	}
	ops.readFile = func(context.Context, string, int64) ([]byte, error) {
		reads++
		return nil, errors.New("profile read must not follow known directory failure")
	}
	ops.close = func(owned io.Closer) error { return snapshotJoin(closeOwned(owned), closeFault) }
	profiles, err := snapshotContext(ctx, store, ops)
	if profiles != nil || !errors.Is(err, readFault) || !errors.Is(err, closeFault) || !errors.Is(err, context.Canceled) {
		t.Fatal("snapshot lost read/close/cancel causes", err)
	}
	if reads != 0 || closed["directory:profiles"] != 1 || closed[".profiles.lock"] != 1 {
		t.Fatal("snapshot continued or repeated ownership", reads, closed)
	}
}
func TestSnapshotIORestoreMarkerRefusalObservesEarlyLeaseClose(t *testing.T) {
	f := newSnapshotIOFixture(t)
	store := f.store(t)
	if err := os.WriteFile(filepath.Join(store.Root, restoreMarker), []byte("retained marker"), 0600); err != nil {
		t.Fatal(err)
	}
	ops, _, closed := snapshotObservedOps(t, f)
	fault := errors.New("injected early lease close")
	closeOwned := ops.close
	ops.close = func(owned io.Closer) error { return snapshotJoin(closeOwned(owned), fault) }
	profiles, err := snapshotContext(context.Background(), store, ops)
	if profiles != nil || !errors.Is(err, ErrRestoreIncomplete) || !errors.Is(err, fault) {
		t.Fatal("early refusal lost close cause", err)
	}
	if closed[".profiles.lock"] != 1 || len(closed) != 1 {
		t.Fatal("unexpected early ownership", closed)
	}
}
func TestSnapshotIOReadCofailureClearsUnadoptedBytes(t *testing.T) {
	f := newSnapshotIOFixture(t)
	store := f.store(t)
	ops, _, _ := snapshotObservedOps(t, f)
	read := ops.readFile
	fault := errors.New("injected closed read cofailure")
	var returned []byte
	ops.readFile = func(ctx context.Context, path string, limit int64) ([]byte, error) {
		data, err := read(ctx, path, limit)
		if err != nil {
			return data, err
		}
		returned = data
		return data, fault
	}
	profiles, err := snapshotContext(context.Background(), store, ops)
	if profiles != nil || !errors.Is(err, fault) {
		t.Fatal("failed read adopted profiles", err)
	}
	if len(returned) == 0 || !bytes.Equal(returned, make([]byte, len(returned))) {
		t.Fatal("unadopted profile bytes were retained")
	}
}
func TestSnapshotIODirectoryCloseAndCancellationWithholdEntries(t *testing.T) {
	f := newSnapshotIOFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "owned"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ops, _, closed := snapshotObservedOps(t, f)
	closeOwned := ops.close
	fault := errors.New("injected directory close")
	ops.close = func(owned io.Closer) error { err := closeOwned(owned); cancel(); return snapshotJoin(err, fault) }
	entries, err := restoreDirectoryContext(ctx, f.root, ops)
	if entries != nil || !errors.Is(err, fault) || !errors.Is(err, context.Canceled) {
		t.Fatal("directory entries adopted before checked close", err)
	}
	if closed["directory:"+filepath.Base(f.root)] != 1 {
		t.Fatal("directory was not closed exactly once")
	}
}
func TestSnapshotIODirectoryBoundsAndChangedNativeBindingRefuse(t *testing.T) {
	for _, mode := range []string{"bounds", "binding"} {
		t.Run(mode, func(t *testing.T) {
			f := newSnapshotIOFixture(t)
			store := f.store(t)
			ops, _, closed := snapshotObservedOps(t, f)
			if mode == "bounds" {
				read := ops.readDirectory
				ops.readDirectory = func(file *os.File, n int) ([]os.DirEntry, error) {
					entries, err := read(file, n)
					if err != nil && err != io.EOF {
						return nil, err
					}
					result := make([]os.DirEntry, 129)
					for i := range result {
						result[i] = entries[0]
					}
					return result, nil
				}
			}
			if mode == "binding" {
				opened := ops.opened
				queries := 0
				ops.opened = func(file *os.File) (state fileidentity.State, err error) {
					state, err = opened(file)
					queries++
					if queries == 2 {
						state.ID.FileID[0] ^= 1
					}
					return state, err
				}
			}
			profiles, err := snapshotContext(context.Background(), store, ops)
			if profiles != nil || err == nil {
				t.Fatal("invalid directory result was adopted")
			}
			if closed["directory:profiles"] != 1 || closed[".profiles.lock"] != 1 {
				t.Fatal("failure leaked owners", closed)
			}
		})
	}
}
func TestRestoreSnapshotIOPublicationWaitsForAllFinalClosesAndReturnsCofailures(t *testing.T) {
	f := newSnapshotIOFixture(t)
	root := filepath.Join(f.root, "restored")
	ops, names, closed := snapshotObservedOps(t, f)
	closeOwned := ops.close
	profileFault, controllerFault := errors.New("injected profile lease close"), errors.New("injected controller lease close")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	var result error
	ops.close = func(owned io.Closer) error {
		if names[owned] == ".profiles.lock" {
			close(entered)
			<-release
		}
		err := closeOwned(owned)
		if names[owned] == ".profiles.lock" {
			return snapshotJoin(err, profileFault)
		}
		if names[owned] == ".controller.lock" {
			return snapshotJoin(err, controllerFault)
		}
		return err
	}
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			f.preserve.Store(true)
			t.Error("unconfirmed restore retained")
		}
	})
	go func() {
		result = restoreSnapshotWithIO(context.Background(), root, snapshotFixture(), false, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }), ops)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(8 * time.Second):
		f.preserve.Store(true)
		t.Fatal("restore did not reach final close")
	}
	select {
	case <-done:
		t.Fatal("restore returned before its final close")
	default:
	}
	if _, err := os.Stat(filepath.Join(root, "profiles", snapshotFixture()[0].ID+".json")); err != nil {
		t.Fatal("actual publication not observed")
	}
	if _, err := os.Lstat(filepath.Join(root, restoreMarker)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("test did not reach post-publication marker removal")
	}
	if lease, err := filelock.TryAcquire(filepath.Join(root, ".profiles.lock")); !errors.Is(err, filelock.ErrBusy) {
		if lease != nil {
			if closeErr := lease.Close(); closeErr != nil {
				f.preserve.Store(true)
				t.Error("unexpected lock probe close unconfirmed")
			}
		}
		t.Fatal("original profile owner not retained through close barrier")
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		f.preserve.Store(true)
		t.Fatal("restore final close did not finish")
	}
	if !errors.Is(result, profileFault) || !errors.Is(result, controllerFault) {
		t.Fatal("post-publication close cofailure was lost", result)
	}
	if closed[".profiles.lock"] != 1 || closed[".controller.lock"] != 1 {
		t.Fatal("restore repeated or skipped lease close", closed)
	}
	got, err := readRestoreFile(filepath.Join(root, "profiles", snapshotFixture()[0].ID+".json"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(bytes.NewReader(got))
	if err != nil || !reflect.DeepEqual(p, snapshotFixture()[0]) {
		t.Fatal("close failure changed published data", err)
	}
}
func TestRestoreSnapshotIOAcquisitionFailureClosesControllerAndRetainsCauses(t *testing.T) {
	f := newSnapshotIOFixture(t)
	root := filepath.Join(f.root, "restored")
	ops, _, closed := snapshotObservedOps(t, f)
	acquire, closeOwned := ops.acquire, ops.close
	first, closeFault := errors.New("injected profile admission"), errors.New("injected controller close")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ops.acquire = func(ctx context.Context, path string, immediate bool) (io.Closer, error) {
		if filepath.Base(path) == ".profiles.lock" {
			cancel()
			return nil, first
		}
		return acquire(ctx, path, immediate)
	}
	ops.close = func(owned io.Closer) error { return snapshotJoin(closeOwned(owned), closeFault) }
	err := restoreSnapshotWithIO(ctx, root, snapshotFixture(), false, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }), ops)
	if !errors.Is(err, first) || !errors.Is(err, closeFault) || !errors.Is(err, context.Canceled) {
		t.Fatal("acquisition/close/context causes were lost", err)
	}
	if closed[".controller.lock"] != 1 || closed[".profiles.lock"] != 0 {
		t.Fatal("unexpected failed-admission ownership", closed)
	}
	if _, err := os.Stat(filepath.Join(root, "profiles")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed admission published profiles")
	}
}

type snapshotFaultSyncFile struct {
	file                          *os.File
	syncFault, closeFault         error
	nativeSyncErr, nativeCloseErr error
	syncs, closes                 int
}

func (f *snapshotFaultSyncFile) Sync() error {
	f.syncs++
	f.nativeSyncErr = f.file.Sync()
	return snapshotJoin(f.nativeSyncErr, f.syncFault)
}
func (f *snapshotFaultSyncFile) Close() error {
	f.closes++
	f.nativeCloseErr = f.file.Close()
	if f.nativeCloseErr != nil {
		return f.nativeCloseErr
	}
	return f.closeFault
}
func TestSnapshotIOSyncAndCloseCofailuresBothSurviveActualOwnedFile(t *testing.T) {
	f := newSnapshotIOFixture(t)
	file, err := os.OpenFile(filepath.Join(f.root, "owned"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("owned sync fixture")); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			f.preserve.Store(true)
		}
		t.Fatal(err)
	}
	owned := &snapshotFaultSyncFile{file: file, syncFault: errors.New("injected sync cofailure"), closeFault: errors.New("injected close cofailure")}
	err = syncSnapshotOwned(owned)
	if owned.nativeSyncErr != nil || owned.nativeCloseErr != nil {
		f.preserve.Store(true)
		t.Fatal("actual owned sync/close failed before injection")
	}
	if !errors.Is(err, owned.syncFault) || !errors.Is(err, owned.closeFault) || owned.syncs != 1 || owned.closes != 1 {
		t.Fatal("sync/close observations were lost or repeated", err)
	}
	if n, err := file.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
		f.preserve.Store(true)
		t.Fatal("actual file close not observed", n, err)
	}
}
