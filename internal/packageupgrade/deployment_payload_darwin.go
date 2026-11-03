//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// The seal must come from the newly built trusted packaging helper, never the
// installed app, an incoming self-description alone, environment or caller path.
// Publisher/notarization validation remains a separate requirement.
func verifyDeploymentBundle(app *os.File, identity deploymentIdentity) (Manifest, []byte, error) {
	encoded, e := readPath(app, ManifestName, 2<<20)
	if e != nil {
		return Manifest{}, nil, e
	}
	return verifyDeploymentInventory(app, identity, encoded, true)
}

const detachedDeploymentManifest = "INSTALL-MANIFEST.json"

// Inventory location is determined by an exact, protected container layout.
// One app is the legacy embedded format; app plus sidecar is the new format.
// Missing, duplicate, linked, or unexpected objects never trigger a fallback.
func openDeploymentBundle(container *os.File) (*os.File, []byte, bool, error) {
	if e := deploymentObject(container, true, 0, 0755); e != nil {
		return nil, nil, false, e
	}
	entries, e := deploymentEntries(container, 0, 2)
	if e != nil {
		return nil, nil, false, e
	}
	hasApp, hasSidecar := false, false
	for _, entry := range entries {
		switch entry.Name() {
		case "AccessWeaver.app":
			hasApp = true
		case detachedDeploymentManifest:
			hasSidecar = true
		default:
			return nil, nil, false, errors.New("deployment bundle container inventory differs")
		}
	}
	if !hasApp || len(entries) != 1 && !hasSidecar {
		return nil, nil, false, errors.New("deployment bundle container is incomplete")
	}
	app, e := directoryAt(container, "AccessWeaver.app")
	if e != nil {
		return nil, nil, false, e
	}
	var encoded []byte
	if hasSidecar {
		var st syscall.Stat_t
		encoded, st, e = readAt(container, detachedDeploymentManifest, 2<<20)
		if e == nil && st.Mode&07777 != 0644 {
			e = errors.New("detached deployment manifest mode differs")
		}
	} else {
		encoded, e = readPath(app, ManifestName, 2<<20)
	}
	if e != nil {
		return nil, nil, false, errors.Join(e, app.Close())
	}
	return app, encoded, !hasSidecar, nil
}

func verifyDeploymentInventory(app *os.File, identity deploymentIdentity, encoded []byte, embedded bool) (Manifest, []byte, error) {
	var empty Manifest
	if e := identity.validate(); e != nil {
		return empty, nil, e
	}
	if e := deploymentObject(app, true, 0, 0755); e != nil {
		return empty, nil, e
	}
	if digest(encoded) != identity.ManifestSHA256 {
		return empty, nil, errors.New("incoming deployment manifest seal differs")
	}
	m, e := DecodeManifest(encoded)
	if e != nil {
		return empty, nil, e
	}
	fd, e := unix.Openat(int(app.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return empty, nil, e
	}
	fresh := os.NewFile(uintptr(fd), app.Name())
	important, e := inspectBundleInventory(fresh, m, encoded, embedded)
	e = errors.Join(e, fresh.Close())
	if e != nil {
		return empty, nil, e
	}
	build, e := decodeBuild(important["Contents/Resources/BUILD-INFO.json"], runtime.GOARCH)
	if e != nil {
		return empty, nil, e
	}
	if build.Version != identity.Version {
		return empty, nil, errors.New("incoming deployment release differs")
	}
	if e = checkPlist(important["Contents/Info.plist"], build.Version); e != nil {
		return empty, nil, e
	}
	core := important["Contents/MacOS/accessweaver"]
	cpu := uint32(0x01000007)
	if runtime.GOARCH == "arm64" {
		cpu = 0x0100000c
	}
	if digest(core) != identity.PayloadSHA256 || len(core) < 32 || binary.LittleEndian.Uint32(core) != 0xfeedfacf || binary.LittleEndian.Uint32(core[4:]) != cpu || binary.LittleEndian.Uint32(core[12:]) != 2 {
		return empty, nil, errors.New("incoming deployment payload seal/native identity differs")
	}
	return m, encoded, nil
}
func deploymentSubdirectory(root *os.File, path string) (*os.File, error) {
	current := root
	owned := false
	for _, part := range strings.Split(path, "/") {
		next, e := directoryAt(current, part)
		if owned {
			current.Close()
		}
		if e != nil {
			return nil, e
		}
		current = next
		owned = true
	}
	return current, nil
}
func deploymentFileParent(root *os.File, path string) (*os.File, string, error) {
	parts := strings.Split(path, "/")
	if len(parts) == 1 {
		return nil, parts[0], nil
	}
	parent, e := deploymentSubdirectory(root, strings.Join(parts[:len(parts)-1], "/"))
	return parent, parts[len(parts)-1], e
}
func (s *deploymentStore) verifySlot(slot deploymentSlot) error {
	dir, e := s.openSlot(slot)
	if e != nil {
		return e
	}
	defer dir.Close()
	if e = deploymentObject(dir, true, 0, 0755); e != nil {
		return e
	}
	app, encoded, embedded, e := openDeploymentBundle(dir)
	if e != nil {
		return e
	}
	defer app.Close()
	_, _, e = verifyDeploymentInventory(app, slot.Identity, encoded, embedded)
	return e
}

// activatePrepared is also the recovery route after a complete copy or a
// possibly-published record. It never resumes a partial copy, runs installed
// code, overwrites a slot or deletes retained data.
func (s *deploymentStore) activatePrepared(slot deploymentSlot) (bool, error) {
	if s.owner != 0 {
		return false, errors.New("deployment activation requires root-owned storage")
	}
	if e := s.checkRoot(); e != nil {
		return false, e
	}
	if e := s.verifySlot(slot); e != nil {
		return false, e
	}
	if s.state.Active == slot {
		return true, fullDeploymentSync(s.root)
	}
	next, e := s.state.activate(slot)
	if e != nil {
		return false, e
	}
	if s.state.Active != (deploymentSlot{}) {
		if e = s.verifySlot(s.state.Active); e != nil {
			return false, e
		}
	}
	return s.commit(next)
}
func (s *deploymentStore) copyAndActivate(slot deploymentSlot, source *os.File) (bool, error) {
	encoded, e := readPath(source, ManifestName, 2<<20)
	if e != nil {
		return false, e
	}
	return s.copyBundleAndActivate(slot, source, encoded, true)
}
func (s *deploymentStore) copyIncomingAndActivate(slot deploymentSlot, container *os.File) (published bool, err error) {
	app, encoded, embedded, e := openDeploymentBundle(container)
	if e != nil {
		return false, e
	}
	defer func() { err = errors.Join(err, app.Close()) }()
	return s.copyBundleAndActivate(slot, app, encoded, embedded)
}
func (s *deploymentStore) copyBundleAndActivate(slot deploymentSlot, source *os.File, inventory []byte, embedded bool) (bool, error) {
	if s.owner != 0 {
		return false, errors.New("deployment copy requires root-owned storage")
	}
	// Check the generation before touching the reserved directory.
	if _, e := s.state.activate(slot); e != nil {
		return false, e
	}
	m, encoded, e := verifyDeploymentInventory(source, slot.Identity, inventory, embedded)
	if e != nil {
		return false, e
	}
	dir, e := s.openSlot(slot)
	if e != nil {
		return false, e
	}
	defer dir.Close()
	entries, e := deploymentEntries(dir, 0, 1)
	if e != nil {
		return false, e
	}
	if len(entries) != 0 {
		return false, errors.New("deployment copy is partial or complete; preserve and inspect before recovery")
	}
	app, e := darwintrust.CreateDirectoryAt(dir, "AccessWeaver.app", 0)
	if e != nil {
		return false, e
	}
	defer app.Close()
	if e = s.phase("payload-reserved"); e != nil {
		return false, e
	}
	dirs := append([]Directory{}, m.Directories...)
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Path < dirs[j].Path })
	for _, d := range dirs {
		parent, name, e := deploymentFileParent(app, d.Path)
		if e != nil {
			return false, e
		}
		if parent == nil {
			parent = app
		}
		child, e := darwintrust.CreateDirectoryAt(parent, name, 0)
		if parent != app {
			parent.Close()
		}
		if e != nil {
			return false, e
		}
		// These are new objects inside the private uncommitted slot.
		e = errors.Join(child.Chmod(0755), fullDeploymentSync(child), child.Close())
		if e != nil {
			return false, e
		}
	}
	files := append([]File{}, m.Files...)
	if embedded {
		files = append(files, File{Path: ManifestName, Bytes: int64(len(encoded)), SHA256: digest(encoded), Mode: "0644"})
	} else {
		f, createErr := darwintrust.CreateRegularAt(dir, detachedDeploymentManifest, 0)
		if createErr != nil {
			return false, createErr
		}
		n, writeErr := f.Write(encoded)
		if writeErr == nil && n != len(encoded) {
			writeErr = io.ErrShortWrite
		}
		if e = errors.Join(writeErr, f.Chmod(0644), fullDeploymentSync(f), f.Close(), fullDeploymentSync(dir)); e != nil {
			return false, e
		}
		if e = s.phase("payload-manifest-durable"); e != nil {
			return false, e
		}
	}
	for _, record := range files {
		data, e := readPath(source, record.Path, 64<<20)
		if e != nil {
			return false, e
		}
		if int64(len(data)) != record.Bytes || digest(data) != record.SHA256 {
			return false, errors.New("incoming deployment changed during copy")
		}
		parent, name, e := deploymentFileParent(app, record.Path)
		if e != nil {
			return false, e
		}
		if parent == nil {
			parent = app
		}
		f, e := darwintrust.CreateRegularAt(parent, name, 0)
		if parent != app {
			parent.Close()
		}
		if e != nil {
			return false, e
		}
		mode := os.FileMode(0644)
		if record.Mode == "0755" {
			mode = 0755
		}
		n, writeErr := f.Write(data)
		if writeErr == nil && n != len(data) {
			writeErr = io.ErrShortWrite
		}
		e = errors.Join(writeErr, f.Chmod(mode), fullDeploymentSync(f), f.Close())
		if e != nil {
			return false, e
		}
		if e = s.phase("payload-file-durable"); e != nil {
			return false, e
		}
	}
	// Flush child entries before parents. Never publish before the independent
	// copied inventory and native build identity have been checked in full.
	for i := len(dirs) - 1; i >= 0; i-- {
		child, e := deploymentSubdirectory(app, dirs[i].Path)
		if e != nil {
			return false, e
		}
		e = errors.Join(fullDeploymentSync(child), child.Close())
		if e != nil {
			return false, e
		}
	}
	if e = errors.Join(app.Chmod(0755), fullDeploymentSync(app), dir.Chmod(0755), fullDeploymentSync(dir), fullDeploymentSync(s.versions)); e != nil {
		return false, e
	}
	if e = s.phase("payload-complete"); e != nil {
		return false, e
	}
	return s.activatePrepared(slot)
}
