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
	return verifyDeploymentInventory(app, identity, encoded, true, nil)
}

// Accept only three exact protected layouts: legacy embedded metadata, a
// legacy detached inventory, or schema2 with both inventory and SBOM detached.
// Layout alone never grants trust: inventory/core seals are verified below.
func openDeploymentBundle(container *os.File) (*os.File, []byte, []byte, bool, error) {
	return nativeRuntimeReads().openDeploymentBundle(container)
}
func (r runtimeReadOps) openDeploymentBundle(container *os.File) (*os.File, []byte, []byte, bool, error) {
	if e := deploymentObject(container, true, 0, 0755); e != nil {
		return nil, nil, nil, false, e
	}
	entries, e := r.deploymentEntries(container, 0, 3)
	if e != nil {
		return nil, nil, nil, false, e
	}
	hasApp, hasSidecar, hasSBOM := false, false, false
	for _, entry := range entries {
		switch entry.Name() {
		case "AccessWeaver.app":
			hasApp = true
		case detachedDeploymentManifest:
			hasSidecar = true
		case PayloadSBOMName:
			hasSBOM = true
		default:
			return nil, nil, nil, false, errors.New("deployment bundle container inventory differs")
		}
	}
	if !hasApp || len(entries) != 1 && !hasSidecar || hasSBOM && !hasSidecar {
		return nil, nil, nil, false, errors.New("deployment bundle container is incomplete")
	}
	app, e := r.directoryAt(container, "AccessWeaver.app")
	if e != nil {
		return nil, nil, nil, false, e
	}
	var encoded, sbom []byte
	if hasSidecar {
		encoded, e = r.readDetachedDeploymentFile(container, detachedDeploymentManifest, 2<<20)
	} else {
		encoded, e = r.readPath(app, ManifestName, 2<<20)
	}
	if e == nil && hasSBOM {
		sbom, e = r.readDetachedDeploymentFile(container, PayloadSBOMName, maxPayloadSBOM)
	}
	if e != nil {
		return nil, nil, nil, false, r.finish(app, e)
	}
	return app, encoded, sbom, !hasSidecar, nil
}
func readDetachedDeploymentFile(container *os.File, name string, limit int64) ([]byte, error) {
	return nativeRuntimeReads().readDetachedDeploymentFile(container, name, limit)
}
func (r runtimeReadOps) readDetachedDeploymentFile(container *os.File, name string, limit int64) ([]byte, error) {
	data, st, e := r.readAt(container, name, limit)
	if e != nil {
		return nil, e
	}
	if st.Mode&07777 != 0644 || len(data) == 0 {
		return nil, errors.New("detached deployment metadata mode/size differs")
	}
	return data, nil
}

func verifyDeploymentInventory(app *os.File, identity deploymentIdentity, encoded []byte, embedded bool, sbom []byte) (Manifest, []byte, error) {
	return nativeRuntimeReads().verifyDeploymentInventory(app, identity, encoded, embedded, sbom)
}
func (r runtimeReadOps) verifyDeploymentInventory(app *os.File, identity deploymentIdentity, encoded []byte, embedded bool, sbom []byte) (Manifest, []byte, error) {
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
	if m.SchemaVersion == 2 {
		if embedded || int64(len(sbom)) != m.PayloadSBOM.Bytes || digest(sbom) != m.PayloadSBOM.SHA256 {
			return empty, nil, errors.New("detached payload SBOM seal/layout differs")
		}
	} else if len(sbom) != 0 {
		return empty, nil, errors.New("legacy deployment has unexpected detached SBOM")
	}
	fd, e := unix.Openat(int(app.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return empty, nil, e
	}
	fresh := os.NewFile(uintptr(fd), app.Name())
	important, e := r.inspectBundleInventory(fresh, m, encoded, embedded)
	e = r.finish(fresh, e)
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
	return nativeRuntimeReads().subdirectory(root, path)
}
func (r runtimeReadOps) subdirectory(root *os.File, path string) (*os.File, error) {
	current := root
	owned := false
	for _, part := range strings.Split(path, "/") {
		next, err := r.directoryAt(current, part)
		if owned {
			err = r.finish(current, err)
		}
		if err != nil {
			if next != nil {
				err = r.finish(next, err)
			}
			return nil, err
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
	return nativeRuntimeReads().verifySlot(s, slot)
}
func (r runtimeReadOps) verifySlot(s *deploymentStore, slot deploymentSlot) (failure error) {
	dir, e := r.openSlot(s, slot)
	if e != nil {
		return e
	}
	defer func() { failure = r.finish(dir, failure) }()
	if e = deploymentObject(dir, true, 0, 0755); e != nil {
		return e
	}
	app, encoded, sbom, embedded, e := r.openDeploymentBundle(dir)
	if e != nil {
		return e
	}
	defer func() { failure = r.finish(app, failure) }()
	_, _, e = r.verifyDeploymentInventory(app, slot.Identity, encoded, embedded, sbom)
	return e
}

// activatePrepared is also the recovery route after a complete copy or a
// possibly-published record. It never resumes a partial copy, runs installed
// code, overwrites a slot or deletes retained data.
func (s *deploymentStore) activatePrepared(slot deploymentSlot) (bool, error) {
	return nativeDeploymentCompletion().activatePrepared(s, slot)
}
func (d deploymentCompletion) activatePrepared(s *deploymentStore, slot deploymentSlot) (bool, error) {
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
	return d.commit(s, next)
}
func (s *deploymentStore) copyAndActivate(slot deploymentSlot, source *os.File) (bool, error) {
	encoded, e := readPath(source, ManifestName, 2<<20)
	if e != nil {
		return false, e
	}
	return s.copyBundleAndActivate(slot, source, encoded, true, nil)
}
func (s *deploymentStore) copyIncomingAndActivate(slot deploymentSlot, container *os.File) (bool, error) {
	return nativeDeploymentCompletion().copyIncomingAndActivate(s, slot, container)
}
func (d deploymentCompletion) copyIncomingAndActivate(s *deploymentStore, slot deploymentSlot, container *os.File) (published bool, err error) {
	app, encoded, sbom, embedded, e := openDeploymentBundle(container)
	if e != nil {
		return false, e
	}
	defer func() { err = d.finish(app, err) }()
	return d.copyBundleAndActivate(s, slot, app, encoded, embedded, sbom)
}
func (s *deploymentStore) copyBundleAndActivate(slot deploymentSlot, source *os.File, inventory []byte, embedded bool, sbom []byte) (bool, error) {
	return nativeDeploymentCompletion().copyBundleAndActivate(s, slot, source, inventory, embedded, sbom)
}
func (d deploymentCompletion) copyBundleAndActivate(s *deploymentStore, slot deploymentSlot, source *os.File, inventory []byte, embedded bool, sbom []byte) (published bool, failure error) {
	if s.owner != 0 {
		return false, errors.New("deployment copy requires root-owned storage")
	}
	// Check the generation before touching the reserved directory.
	if _, e := s.state.activate(slot); e != nil {
		return false, e
	}
	m, encoded, e := verifyDeploymentInventory(source, slot.Identity, inventory, embedded, sbom)
	if e != nil {
		return false, e
	}
	dir, e := s.openSlot(slot)
	if e != nil {
		return false, e
	}
	defer func() { failure = d.finish(dir, failure) }()
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
	defer func() { failure = d.finish(app, failure) }()
	if e = s.phase("payload-reserved"); e != nil {
		return false, e
	}
	dirs := append([]Directory{}, m.Directories...)
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Path < dirs[j].Path })
	for _, directory := range dirs {
		parent, name, e := deploymentFileParent(app, directory.Path)
		if e != nil {
			return false, e
		}
		if parent == nil {
			parent = app
		}
		child, e := darwintrust.CreateDirectoryAt(parent, name, 0)
		if parent != app {
			e = d.finish(parent, e)
		}
		if e != nil {
			return false, d.finish(child, e)
		}
		// These are new objects inside the private uncommitted slot.
		e = d.finish(child, errors.Join(child.Chmod(0755), fullDeploymentSync(child)))
		if e != nil {
			return false, e
		}
	}
	files := append([]File{}, m.Files...)
	if embedded {
		files = append(files, File{Path: ManifestName, Bytes: int64(len(encoded)), SHA256: digest(encoded), Mode: "0644"})
	} else {
		if e = d.writeDetachedDeploymentFile(dir, detachedDeploymentManifest, encoded); e != nil {
			return false, e
		}
		if e = s.phase("payload-manifest-durable"); e != nil {
			return false, e
		}
		if m.SchemaVersion == 2 {
			if e = d.writeDetachedDeploymentFile(dir, PayloadSBOMName, sbom); e != nil {
				return false, e
			}
			if e = s.phase("payload-sbom-durable"); e != nil {
				return false, e
			}
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
			e = d.finish(parent, e)
		}
		if e != nil {
			return false, d.finish(f, e)
		}
		mode := os.FileMode(0644)
		if record.Mode == "0755" {
			mode = 0755
		}
		n, writeErr := f.Write(data)
		if writeErr == nil && n != len(data) {
			writeErr = io.ErrShortWrite
		}
		e = d.finish(f, errors.Join(writeErr, f.Chmod(mode), fullDeploymentSync(f)))
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
		e = d.finish(child, fullDeploymentSync(child))
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
	// Finalize both owned payload metadata handles before activation. Clear
	// each pointer before attempting Close so no deferred path can repeat it.
	finishedApp := app
	app = nil
	e = d.finish(finishedApp, nil)
	finishedDir := dir
	dir = nil
	e = d.finish(finishedDir, e)
	if e != nil {
		return false, e
	}
	return d.activatePrepared(s, slot)
}

// Create only in the private uncommitted slot. Partial metadata is retained;
// neither a missing sibling nor a failed flush authorizes repair/publication.
func writeDetachedDeploymentFile(container *os.File, name string, data []byte) error {
	return nativeDeploymentCompletion().writeDetachedDeploymentFile(container, name, data)
}
func (d deploymentCompletion) writeDetachedDeploymentFile(container *os.File, name string, data []byte) error {
	f, e := darwintrust.CreateRegularAt(container, name, 0)
	if e != nil {
		return e
	}
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(d.finish(f, errors.Join(writeErr, f.Chmod(0644), fullDeploymentSync(f))), fullDeploymentSync(container))
}
