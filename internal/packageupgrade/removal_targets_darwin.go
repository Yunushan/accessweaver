//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// This is a bounded read-only intact observation, not a mutation capability.
// Journaled known absences are handled only by the separate protected-object transaction.
type removalTargetVerification struct {
	roots, files, directories int
	planSHA256                string
}
type removalTargetParent struct {
	file  *os.File
	owned bool
	check func() error
}

func (p removalTargetParent) Close() error {
	if p.owned && p.file != nil {
		return p.file.Close()
	}
	return nil
}

// The alternate resolver is private and used only by owned hosted fixtures.
// No environment, CLI or package phase selects another filesystem authority.
type removalParentResolver func(string) (removalTargetParent, error)

func (r *removalIntentStore) verifyIntactTargets(ctx context.Context) (removalTargetVerification, error) {
	return r.verifyIntactTargetsUsing(ctx, r.fixedTargetParent)
}
func (r *removalIntentStore) verifyIntactTargetsUsing(ctx context.Context, resolve removalParentResolver) (removalTargetVerification, error) {
	var zero removalTargetVerification
	if r == nil || r.store == nil || r.store.owner != 0 || r.store.current == nil || r.store.runtimeLock == nil || resolve == nil {
		return zero, errors.New("removal target verification requires an open root-owned leased intent")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result := removalTargetVerification{planSHA256: r.fence.PlanSHA256}
	for pass := 0; pass < 2; pass++ {
		if bounded.Err() != nil {
			return zero, errors.New("removal target verification deadline exceeded")
		}
		if e := r.verifyIntentMetadata(); e != nil {
			return zero, e
		}
		for _, expected := range r.plan.Roots {
			if e := r.verifyIntactTarget(bounded, expected, resolve); e != nil {
				return zero, e
			}
			if pass == 0 {
				result.roots++
				for _, object := range expected.Objects {
					if object.Kind == "file" {
						result.files++
					} else {
						result.directories++
					}
				}
			}
		}
		if e := r.verifyIntentMetadata(); e != nil {
			return zero, e
		}
	}
	if bounded.Err() != nil {
		return zero, errors.New("removal target verification deadline exceeded")
	}
	return result, nil
}
func (r *removalIntentStore) verifyIntentMetadata() error {
	s := r.store
	if e := r.fence.validatePlan(s.state, r.plan); e != nil {
		return e
	}
	if e := verifyRemovalPlanAuthority(s, r.plan.Authority); e != nil {
		return e
	}
	current, plan, record, e := readRemovalBundle(s.current, s.owner)
	if e != nil {
		return e
	}
	if current != r.fence || !bytes.Equal(record, s.encoded) || sameRemovalPlans(r.plan, plan) != nil {
		return errors.New("removal intent changed before target verification")
	}
	before, history, e := verifyRemovalPlanHistory(s, r.plan, r.fence.DisplacedRecord, "")
	if e != nil {
		return e
	}
	if e = verifyRemovalPlanSlots(s, r.plan, before, history); e != nil {
		return e
	}
	return sameDeploymentEntry(s.root, "state", s.current, s.owner)
}
func (r *removalIntentStore) verifyIntactTarget(ctx context.Context, expected removalPlanRoot, resolve removalParentResolver) error {
	return r.verifyTargetWithNamespace(ctx, expected, r.plan, resolve)
}
func (r *removalIntentStore) verifyTargetWithNamespace(ctx context.Context, expected removalPlanRoot, namespace removalPlan, resolve removalParentResolver) (result error) {
	if expected.Kind == "public" {
		_, _, journal, e := readRemovalQuarantineAt(r.store.current, 0, r.fence, r.plan)
		if e != nil {
			return e
		}
		if journal.completed == 1 {
			if e = r.checkPublicAbsent(resolve); e != nil {
				return e
			}
			if len(expected.Objects) > 0 {
				if matches, e := r.quarantineRootMatches(); e != nil || !matches {
					return errors.Join(e, errors.New("quarantined public root changed"))
				}
			}
			defer func() { result = errors.Join(result, r.checkPublicAbsent(resolve)) }()
			var protected removalParentResolver
			remaining := expected.Objects
			expected, protected, e = r.quarantineTarget()
			expected.Objects = remaining
			if e != nil {
				return e
			}
			return r.verifyTargetAtNamespace(ctx, expected, namespace, protected)
		}
	}
	return r.verifyTargetAtNamespace(ctx, expected, namespace, resolve)
}
func (r *removalIntentStore) verifyTargetAtNamespace(ctx context.Context, expected removalPlanRoot, namespace removalPlan, resolve removalParentResolver) (result error) {
	if ctx.Err() != nil {
		return errors.New("removal target verification deadline exceeded")
	}
	parent, e := resolve(expected.Kind)
	if e != nil {
		return errors.Join(e, parent.Close())
	}
	if parent.file == nil || parent.check == nil {
		return errors.Join(errors.New("incomplete removal parent resolver"), parent.Close())
	}
	defer func() { result = errors.Join(result, parent.Close()) }()
	if e = parent.check(); e != nil {
		return e
	}
	info, e := parent.file.Stat()
	if e != nil {
		return e
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != expected.ParentDevice || st.Ino != expected.ParentInode {
		return errors.New("removal target parent identity changed")
	}
	if expected.Kind == "core" || expected.Kind == "incoming" {
		if e = verifyRemovalTargetNamespace(parent.file, expected.Kind, namespace); e != nil {
			return e
		}
	}
	if len(expected.Objects) == 0 {
		quarantined := expected.Kind == "public" && expected.Key == removalQuarantineName
		if expected.Kind != "core" && expected.Kind != "incoming" && !quarantined {
			return errors.New("ineligible removal root absence")
		}
		var st unix.Stat_t
		if e = unix.Fstatat(int(parent.file.Fd()), expected.Key, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
			return errors.New("journaled removal root is not absent")
		}
		if quarantined {
			return parent.check()
		}
		return errors.Join(parent.check(), verifyRemovalTargetNamespace(parent.file, expected.Kind, namespace))
	}
	root, e := deploymentDirectory(parent.file, expected.Key, 0, false)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	// Reject a raced root before reading any child. The public parent is
	// administrator-writable; a trusted directory alone is not the saved vnode.
	rootInfo, e := root.Stat()
	if e != nil {
		return e
	}
	rootStat := rootInfo.Sys().(*syscall.Stat_t)
	if uint64(rootStat.Dev) != expected.Objects[0].Device || rootStat.Ino != expected.Objects[0].Inode {
		return errors.New("removal target root changed before traversal")
	}
	if expected.Kind == "receipts" {
		if e = verifyRemovalTargetNamespace(root, "receipts", removalPlan{Roots: []removalPlanRoot{expected}}); e != nil {
			return e
		}
	}
	catalog := removalCatalog{}
	for _, object := range expected.Objects[1:] {
		if object.Kind == "directory" {
			catalog[object.Path] = removalCatalogEntry{directory: true}
		} else {
			catalog[object.Path] = removalCatalogEntry{file: File{object.Path, object.Bytes, object.SHA256, object.Mode}}
		}
	}
	observed, e := captureRemovalTree(ctx, parent.file, root, expected.Kind, expected.Key, expected.Identity, catalog)
	if e != nil {
		return e
	}
	wantRaw, e := json.Marshal(expected)
	if e != nil {
		return e
	}
	gotRaw, e := json.Marshal(observed)
	if e != nil {
		return e
	}
	if !bytes.Equal(wantRaw, gotRaw) {
		return errors.New("removal target vnode, content or metadata changed")
	}
	if e = sameDeploymentEntry(parent.file, expected.Key, root, 0); e != nil {
		return e
	}
	if e = parent.check(); e != nil {
		return e
	}
	if expected.Kind == "core" || expected.Kind == "incoming" {
		return verifyRemovalTargetNamespace(parent.file, expected.Kind, namespace)
	}
	if expected.Kind == "receipts" {
		return verifyRemovalTargetNamespace(root, "receipts", removalPlan{Roots: []removalPlanRoot{expected}})
	}
	return nil
}
func verifyRemovalTargetNamespace(dir *os.File, kind string, plan removalPlan) error {
	expected := map[string]bool{}
	for _, root := range plan.Roots {
		if root.Kind != kind {
			continue
		}
		if kind == "receipts" {
			for _, object := range root.Objects[1:] {
				expected[object.Path] = true
			}
		} else {
			expected[root.Key] = true
		}
	}
	if kind != "core" && kind != "incoming" && kind != "receipts" {
		return errors.New("invalid complete removal namespace")
	}
	limit := len(expected)
	if kind == "receipts" {
		limit = 16384
	}
	entries, e := deploymentEntries(dir, 0, limit)
	if e != nil {
		return e
	}
	seen := 0
	for _, entry := range entries {
		name := entry.Name()
		if kind == "receipts" && !strings.HasPrefix(strings.ToLower(name), BundleID+".") {
			continue
		}
		if !expected[name] {
			return errors.New("unrecorded product object in removal namespace")
		}
		seen++
	}
	if seen != len(expected) {
		return errors.New("planned product object missing from removal namespace")
	}
	return nil
}
func sameRemovalTargetParent(held *os.File, open func() (*os.File, error)) (result error) {
	current, e := open()
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, current.Close()) }()
	a, e := held.Stat()
	if e != nil {
		return e
	}
	b, e := current.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(a, b) {
		return errors.New("fixed removal parent identity changed")
	}
	return nil
}
func (r *removalIntentStore) fixedTargetParent(kind string) (removalTargetParent, error) {
	s := r.store
	checkDeploymentParent := func() error {
		return sameRemovalTargetParent(s.parent, func() (*os.File, error) { return darwintrust.OpenRootDirectory(deploymentParent) })
	}
	if kind == "core" || kind == "incoming" || kind == "registrations" {
		if e := checkDeploymentParent(); e != nil {
			return removalTargetParent{}, e
		}
	}
	switch kind {
	case "core":
		return removalTargetParent{s.versions, false, func() error { return errors.Join(checkDeploymentParent(), s.checkRoot()) }}, nil
	case "incoming":
		file, e := deploymentDirectory(s.parent, deploymentIncoming, 0, false)
		if e != nil {
			return removalTargetParent{}, e
		}
		return removalTargetParent{file, true, func() error {
			return errors.Join(checkDeploymentParent(), sameDeploymentEntry(s.parent, deploymentIncoming, file, 0))
		}}, nil
	case "public":
		file, e := applications()
		if e != nil {
			return removalTargetParent{}, e
		}
		// Read-only tree inspection uses this parent. The separate quarantine
		// transaction permits only a journaled exclusive move, never deletion here.
		return removalTargetParent{file, true, func() error { return sameRemovalTargetParent(file, applications) }}, nil
	case "registrations":
		return removalTargetParent{s.parent, false, func() error {
			return sameRemovalTargetParent(s.parent, func() (*os.File, error) { return darwintrust.OpenRootDirectory(deploymentParent) })
		}}, nil
	case "receipts":
		file, e := darwintrust.OpenRootDirectory("/private/var/db")
		if e != nil {
			return removalTargetParent{}, e
		}
		return removalTargetParent{file, true, func() error {
			return sameRemovalTargetParent(file, func() (*os.File, error) { return darwintrust.OpenRootDirectory("/private/var/db") })
		}}, nil
	default:
		return removalTargetParent{}, errors.New("unknown fixed removal target role")
	}
}
