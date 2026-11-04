//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"sort"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

type removalCatalogEntry struct {
	directory bool
	file      File
}
type removalCatalog map[string]removalCatalogEntry

func removalBundleCatalog(m Manifest, encoded []byte, embedded, container bool, sbom []byte) (removalCatalog, error) {
	catalog := removalCatalog{}
	prefix := ""
	add := func(name string, entry removalCatalogEntry) error {
		if _, found := catalog[name]; found {
			return errors.New("duplicate removal catalog object")
		}
		catalog[name] = entry
		return nil
	}
	if container {
		prefix = "AccessWeaver.app/"
		catalog["AccessWeaver.app"] = removalCatalogEntry{directory: true}
	}
	for _, d := range m.Directories {
		if e := add(prefix+d.Path, removalCatalogEntry{directory: true}); e != nil {
			return nil, e
		}
	}
	for _, f := range m.Files {
		if e := add(prefix+f.Path, removalCatalogEntry{file: f}); e != nil {
			return nil, e
		}
	}
	if embedded {
		if e := add(prefix+ManifestName, removalCatalogEntry{file: File{ManifestName, int64(len(encoded)), digest(encoded), "0644"}}); e != nil {
			return nil, e
		}
	} else if container {
		if e := add(detachedDeploymentManifest, removalCatalogEntry{file: File{detachedDeploymentManifest, int64(len(encoded)), digest(encoded), "0644"}}); e != nil {
			return nil, e
		}
		if len(sbom) > 0 {
			if e := add(PayloadSBOMName, removalCatalogEntry{file: File{PayloadSBOMName, int64(len(sbom)), digest(sbom), "0644"}}); e != nil {
				return nil, e
			}
		}
	}
	return catalog, nil
}

func removalFileStillAt(parent *os.File, name string, want syscall.Stat_t) (result error) {
	file, e := darwintrust.OpenRegularAt(parent, name, 0)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	if e = checkGroup(file); e != nil {
		return e
	}
	info, e := file.Stat()
	if e != nil {
		return e
	}
	if !sameState(want, *info.Sys().(*syscall.Stat_t)) {
		return errors.New("removal file name or metadata changed")
	}
	return nil
}

// The catalog comes only from a verified sealed manifest/registration or the
// selected receipt snapshot. Walking actual names alone cannot authorize an
// unexpected file. The partial-root exception is limited to the receipt DB.
func captureRemovalTree(ctx context.Context, parent, root *os.File, kind, key string, identity deploymentIdentity, catalog removalCatalog) (removalPlanRoot, error) {
	result := removalPlanRoot{Kind: kind, Key: key, Identity: identity, Objects: []removalPlanObject{}}
	if len(catalog) == 0 || len(catalog) > MaxFiles+3 {
		return result, errors.New("removal catalog exceeds extent")
	}
	parentInfo, e := parent.Stat()
	if e != nil {
		return result, e
	}
	parentStat := parentInfo.Sys().(*syscall.Stat_t)
	result.ParentDevice, result.ParentInode = uint64(parentStat.Dev), parentStat.Ino
	children := map[string]map[string]removalCatalogEntry{}
	for name, item := range catalog {
		if !validRemovalObjectPath(kind, name) {
			return result, errors.New("invalid removal catalog path")
		}
		dir := path.Dir(name)
		if children[dir] == nil {
			children[dir] = map[string]removalCatalogEntry{}
		}
		children[dir][path.Base(name)] = item
		if dir != "." {
			ancestor, ok := catalog[dir]
			if !ok || !ancestor.directory {
				return result, errors.New("removal catalog parent is absent")
			}
		}
	}
	var walk func(*os.File, string, int) error
	walk = func(dir *os.File, prefix string, depth int) error {
		if ctx.Err() != nil {
			return errors.New("removal plan deadline exceeded")
		}
		if depth > 33 {
			return errors.New("removal tree exceeds depth")
		}
		if e := deploymentObject(dir, true, 0, 0755); e != nil {
			return e
		}
		before, e := dir.Stat()
		if e != nil {
			return e
		}
		st := before.Sys().(*syscall.Stat_t)
		result.Objects = append(result.Objects, removalPlanObject{Path: prefix, Kind: "directory", Mode: "0755", Device: uint64(st.Dev), Inode: st.Ino})
		expected := children[prefix]
		if kind != "receipts" || prefix != "." {
			actual, e := deploymentEntries(dir, 0, len(expected))
			if e != nil {
				return e
			}
			if len(actual) != len(expected) {
				return errors.New("removal tree catalog inventory differs")
			}
			for _, entry := range actual {
				if _, ok := expected[entry.Name()]; !ok {
					return errors.New("unrecorded removal object")
				}
			}
		}
		names := make([]string, 0, len(expected))
		for name := range expected {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if ctx.Err() != nil {
				return errors.New("removal plan deadline exceeded")
			}
			item := expected[name]
			relative := name
			if prefix != "." {
				relative = prefix + "/" + name
			}
			if item.directory {
				next, e := directoryAt(dir, name)
				if e != nil {
					return e
				}
				walkErr := walk(next, relative, depth+1)
				sameErr := sameDeploymentEntry(dir, name, next, 0)
				if e = errors.Join(walkErr, sameErr, next.Close()); e != nil {
					return e
				}
			} else {
				data, state, e := readAt(dir, name, 64<<20)
				if e != nil {
					return e
				}
				mode := uint16(0644)
				if item.file.Mode == "0755" {
					mode = 0755
				} else if item.file.Mode != "0644" {
					return errors.New("invalid removal catalog file mode")
				}
				if state.Mode&07777 != mode || int64(len(data)) != item.file.Bytes || digest(data) != item.file.SHA256 {
					return errors.New("removal catalog file seal differs")
				}
				if e = removalFileStillAt(dir, name, state); e != nil {
					return e
				}
				result.Objects = append(result.Objects, removalPlanObject{Path: relative, Kind: "file", Mode: item.file.Mode, Device: uint64(state.Dev), Inode: state.Ino, Bytes: int64(len(data)), MtimeNs: state.Mtimespec.Sec*1e9 + state.Mtimespec.Nsec, CtimeNs: state.Ctimespec.Sec*1e9 + state.Ctimespec.Nsec, SHA256: item.file.SHA256})
			}
		}
		after, e := dir.Stat()
		if e != nil {
			return e
		}
		if !sameState(*st, *after.Sys().(*syscall.Stat_t)) {
			return errors.New("removal directory changed during capture")
		}
		return nil
	}
	if e = walk(root, ".", 0); e != nil {
		return result, e
	}
	// "." is the explicit first object, even when a legal filename sorts earlier.
	sort.Slice(result.Objects[1:], func(i, j int) bool { return result.Objects[1+i].Path < result.Objects[1+j].Path })
	return result, nil
}
func captureRemovalBundle(ctx context.Context, parent *os.File, key, kind string, identity deploymentIdentity) (result removalPlanRoot, err error) {
	if ctx.Err() != nil {
		return result, errors.New("removal plan deadline exceeded")
	}
	root, e := deploymentDirectory(parent, key, 0, false)
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	app, encoded, sbom, embedded, e := openDeploymentBundle(root)
	if e != nil {
		return result, e
	}
	m, _, verifyErr := verifyDeploymentInventory(app, identity, encoded, embedded, sbom)
	if e = errors.Join(verifyErr, app.Close()); e != nil {
		return result, e
	}
	catalog, e := removalBundleCatalog(m, encoded, embedded, true, sbom)
	if e != nil {
		return result, e
	}
	result, e = captureRemovalTree(ctx, parent, root, kind, key, identity, catalog)
	if e != nil {
		return result, e
	}
	if e = sameDeploymentEntry(parent, key, root, 0); e != nil {
		return result, e
	}
	return result, nil
}

func (s *deploymentStore) buildRemovalPlan(ctx context.Context, identity deploymentIdentity, desktopSeal string, core removalCoreSnapshot, inputs removalIncomingSnapshot, receipts removalReceiptSnapshot, apps, app, registry *os.File, records []desktopRecord, encoded [][]byte, selected int) (result removalPlan, err error) {
	if ctx.Err() != nil {
		return result, errors.New("removal plan deadline exceeded")
	}
	if s.owner != 0 || selected < 0 || selected >= len(records) || len(records) != len(encoded) || digest(encoded[selected]) != desktopSeal || s.state.Active.Identity != identity {
		return result, errors.New("invalid verified removal-plan selection")
	}
	if e := s.checkRoot(); e != nil {
		return result, e
	}
	authority, e := captureRemovalPlanAuthority(s)
	if e != nil {
		return result, e
	}
	result = removalPlan{SchemaVersion: 2, Generation: s.state.Generation, Active: s.state.Active, DesktopRecordSHA256: desktopSeal, Authority: authority, History: append([]removalRecord{}, core.Records...), Roots: []removalPlanRoot{}}
	header, e := json.Marshal(result)
	if e != nil {
		return result, e
	}
	objects, metadataBytes := 0, len(header)
	appendTree := func(tree removalPlanRoot) error {
		objects += len(tree.Objects)
		encoded, e := json.Marshal(tree)
		if e != nil {
			return e
		}
		metadataBytes += len(encoded) + 1
		if objects > maxRemovalPlanObjects || metadataBytes > maxRemovalPlanBytes {
			return errors.New("removal plan exceeds cumulative metadata budget")
		}
		result.Roots = append(result.Roots, tree)
		return nil
	}
	for _, slot := range core.Slots {
		tree, e := captureRemovalBundle(ctx, s.versions, slot.ID, "core", slot.Identity)
		if e != nil {
			return result, e
		}
		if tree.Objects[0].Device != uint64(slot.Device) || tree.Objects[0].Inode != slot.Inode {
			return result, errors.New("removal core root identity differs")
		}
		if e = appendTree(tree); e != nil {
			return result, e
		}
	}
	incoming, e := deploymentDirectory(s.parent, deploymentIncoming, 0, false)
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, incoming.Close()) }()
	info, e := incoming.Stat()
	if e != nil {
		return result, e
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != inputs.Device || st.Ino != inputs.Inode {
		return result, errors.New("removal incoming parent differs")
	}
	for _, entry := range inputs.Entries {
		tree, e := captureRemovalBundle(ctx, incoming, entry.Identity.ManifestSHA256, "incoming", entry.Identity)
		if e != nil {
			return result, e
		}
		if tree.Objects[0].Device != entry.Device || tree.Objects[0].Inode != entry.Inode {
			return result, errors.New("removal incoming root identity differs")
		}
		if e = appendTree(tree); e != nil {
			return result, e
		}
	}
	catalog, e := removalBundleCatalog(records[selected].Manifest, nil, false, false, nil)
	if e != nil {
		return result, e
	}
	public, e := captureRemovalTree(ctx, apps, app, "public", "AccessWeaver.app", deploymentIdentity{}, catalog)
	if e != nil {
		return result, e
	}
	if e = sameDeploymentEntry(apps, "AccessWeaver.app", app, 0); e != nil {
		return result, e
	}
	if e = appendTree(public); e != nil {
		return result, e
	}
	catalog = removalCatalog{}
	for _, raw := range encoded {
		name := desktopRecordName(raw)
		catalog[name] = removalCatalogEntry{file: File{name, int64(len(raw)), digest(raw), "0644"}}
	}
	registrations, e := captureRemovalTree(ctx, s.parent, registry, "registrations", desktopRoot, deploymentIdentity{}, catalog)
	if e != nil {
		return result, e
	}
	if e = sameDeploymentEntry(s.parent, desktopRoot, registry, 0); e != nil {
		return result, e
	}
	if e = appendTree(registrations); e != nil {
		return result, e
	}
	receiptParent, e := darwintrust.OpenRootDirectory("/private/var/db")
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, receiptParent.Close()) }()
	receiptRoot, e := deploymentDirectory(receiptParent, "receipts", 0, false)
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, receiptRoot.Close()) }()
	info, e = receiptRoot.Stat()
	if e != nil {
		return result, e
	}
	st = info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != receipts.Device || st.Ino != receipts.Inode {
		return result, errors.New("removal receipt root differs")
	}
	catalog = removalCatalog{}
	for _, f := range receipts.Files {
		catalog[f.Name] = removalCatalogEntry{file: File{f.Name, f.Bytes, f.SHA256, "0644"}}
	}
	// The root is itself protected and fixed; unrelated receipts are not copied
	// into the plan. Namespace completeness is checked by the receipt inventory.
	receiptTree, e := captureRemovalTree(ctx, receiptParent, receiptRoot, "receipts", "receipts", deploymentIdentity{}, catalog)
	if e != nil {
		return result, e
	}
	for _, o := range receiptTree.Objects[1:] {
		matched := false
		for _, f := range receipts.Files {
			if o.Path == f.Name && o.Device == f.Device && o.Inode == f.Inode && o.MtimeNs == f.MtimeNs && o.CtimeNs == f.CtimeNs {
				matched = true
				break
			}
		}
		if !matched {
			return result, errors.New("removal receipt file identity changed")
		}
	}
	if e = sameDeploymentEntry(receiptParent, "receipts", receiptRoot, 0); e != nil {
		return result, e
	}
	if e = appendTree(receiptTree); e != nil {
		return result, e
	}
	if e = sameDeploymentEntry(s.parent, deploymentIncoming, incoming, 0); e != nil {
		return result, e
	}
	sort.Slice(result.Roots, func(i, j int) bool {
		a, b := result.Roots[i], result.Roots[j]
		return a.Kind+"\x00"+a.Key < b.Kind+"\x00"+b.Key
	})
	_, e = encodeRemovalPlan(result)
	return result, e
}

func sameRemovalPlans(a, b removalPlan) error {
	before, e := encodeRemovalPlan(a)
	if e != nil {
		return e
	}
	after, e := encodeRemovalPlan(b)
	if e != nil {
		return e
	}
	if !bytes.Equal(before, after) {
		return errors.New("removal per-object plan changed")
	}
	return nil
}
