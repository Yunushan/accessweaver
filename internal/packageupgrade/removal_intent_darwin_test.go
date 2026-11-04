//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

// Synthetic payload entries exercise metadata semantics only. Actual per-file
// capture is separately exercised by the root-copy and whole-product fixtures.
func removalMetadataPlanFixture(t *testing.T, s *deploymentStore) removalPlan {
	t.Helper()
	p := removalFencePlanForStateFixture(s.state)
	var e error
	p.Authority, e = captureRemovalPlanAuthority(s)
	if e != nil {
		t.Fatal(e)
	}
	p.History = []removalRecord{}
	history := []deploymentState{}
	entries, e := deploymentEntries(s.root, s.owner, maxRetainedRecords+4)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "state" && !recordName.MatchString(name) {
			continue
		}
		dir, e := deploymentDirectory(s.root, name, s.owner, false)
		if e != nil {
			t.Fatal(e)
		}
		raw, readErr := s.readRecord(dir)
		info, statErr := dir.Stat()
		if e = errors.Join(readErr, statErr, dir.Close()); e != nil {
			t.Fatal(e)
		}
		state, e := decodeDeployment(raw)
		if e != nil {
			t.Fatal(e)
		}
		st := info.Sys().(*syscall.Stat_t)
		p.History = append(p.History, removalRecord{name, uint64(st.Dev), st.Ino, removalDigest(raw)})
		if name != "state" {
			history = append(history, state)
		}
	}
	sort.Slice(p.History, func(i, j int) bool { return p.History[i].Name < p.History[j].Name })
	slots, e := removalSlots(s.state, s.state.Active.Identity, history)
	if e != nil {
		t.Fatal(e)
	}
	info, e := s.versions.Stat()
	if e != nil {
		t.Fatal(e)
	}
	parent := info.Sys().(*syscall.Stat_t)
	coreTemplate, incomingTemplate := p.Roots[0], p.Roots[1]
	roots := append([]removalPlanRoot{}, p.Roots[2:]...)
	incoming := map[string]bool{}
	byID := map[string]deploymentSlot{}
	used := map[[2]uint64]bool{}
	for _, v := range [][2]uint64{{p.Authority.RootDevice, p.Authority.RootInode}, {p.Authority.WriterDevice, p.Authority.WriterInode}, {p.Authority.RuntimeDevice, p.Authority.RuntimeInode}} {
		used[v] = true
	}
	for _, h := range p.History {
		used[[2]uint64{h.Device, h.Inode}] = true
	}
	for _, slot := range slots {
		core := coreTemplate
		core.Objects = append([]removalPlanObject{}, coreTemplate.Objects...)
		core.Key = slot.ID
		core.Identity = slot.Identity
		core.ParentDevice = uint64(parent.Dev)
		core.ParentInode = parent.Ino
		roots = append(roots, core)
		byID[slot.ID] = slot
		used[[2]uint64{uint64(slot.Device), slot.Inode}] = true
		if !incoming[slot.Identity.ManifestSHA256] {
			input := incomingTemplate
			input.Objects = append([]removalPlanObject{}, incomingTemplate.Objects...)
			input.Key = slot.Identity.ManifestSHA256
			input.Identity = slot.Identity
			roots = append(roots, input)
			incoming[input.Key] = true
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Kind+"\x00"+roots[i].Key < roots[j].Kind+"\x00"+roots[j].Key })
	nonce := uint64(1 << 63)
	for i := range roots {
		for j := range roots[i].Objects {
			o := &roots[i].Objects[j]
			if roots[i].Kind == "core" {
				slot := byID[roots[i].Key]
				o.Device = uint64(slot.Device)
				if j == 0 {
					o.Inode = slot.Inode
					continue
				}
			}
			for {
				nonce++
				if !used[[2]uint64{o.Device, nonce}] {
					break
				}
			}
			o.Inode = nonce
			used[[2]uint64{o.Device, nonce}] = true
		}
	}
	p.Roots = roots
	if _, e = encodeRemovalPlan(p); e != nil {
		t.Fatal(e)
	}
	return p
}
func publishedRemovalMetadataFixture(t *testing.T) (string, removalFence, removalPlan) {
	t.Helper()
	parent := t.TempDir()
	s := deploymentFixtureStore(t, parent, nil)
	if _, e := s.commit(removalFenceState()); e != nil {
		t.Fatal(e)
	}
	plan := removalMetadataPlanFixture(t, s)
	fence, _, e := newRemovalFence(s.state, strings.Repeat("d", 64), strings.Repeat("e", 64), plan)
	if e != nil {
		t.Fatal(e)
	}
	if published, e := s.publishRemovalFence(fence, plan); !published || e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	return parent, fence, plan
}
func reopenRemovalMetadataFixture(parent string, fence removalFence) (*removalIntentStore, error) {
	file, e := os.Open(parent)
	if e != nil {
		return nil, e
	}
	return openRemovalIntentAt(file, uint32(os.Geteuid()), fence.Target.Identity, fence.DesktopRecordSHA256)
}
func TestDarwinRemovalIntentReopensExactMetadataUnderBothLeases(t *testing.T) {
	parent, fence, plan := publishedRemovalMetadataFixture(t)
	intent, e := reopenRemovalMetadataFixture(parent, fence)
	if e != nil {
		t.Fatal(e)
	}
	if intent.fence != fence || sameRemovalPlans(plan, intent.plan) != nil || intent.store.state.Generation != 8 || intent.store.state.Active != (deploymentSlot{}) {
		t.Fatal("reopened intent differs")
	}
	if second, e := reopenRemovalMetadataFixture(parent, fence); e == nil {
		second.Close()
		t.Fatal("second removal writer acquired leases")
	}
	if e = intent.Close(); e != nil {
		t.Fatal(e)
	}
	file, e := os.Open(parent)
	if e != nil {
		t.Fatal(e)
	}
	if ordinary, e := beginDeploymentMode(file, uint32(os.Geteuid()), nil, false); e == nil {
		ordinary.Close()
		t.Fatal("ordinary installer accepted durable removal bundle")
	}
	// A failed ordinary open must not corrupt the still-readable intent.
	again, e := reopenRemovalMetadataFixture(parent, fence)
	if e != nil {
		t.Fatal(e)
	}
	if e = again.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestDarwinRemovalIntentRequiresRuntimeLeaseAndReleasesWriterOnFailure(t *testing.T) {
	parent, fence, _ := publishedRemovalMetadataFixture(t)
	root, e := os.Open(filepath.Join(parent, deploymentRoot))
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	reader, e := runtimeFileAt(root, uint32(os.Geteuid()))
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.Flock(int(reader.Fd()), unix.LOCK_SH|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	if intent, e := reopenRemovalMetadataFixture(parent, fence); e == nil {
		intent.Close()
		t.Fatal("removal ignored serving runtime lease")
	}
	writer, e := darwintrust.OpenRegularAt(root, deploymentLock, uint32(os.Geteuid()))
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.Flock(int(writer.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal("failed reopen leaked writer lease", e)
	}
	if e = writer.Close(); e != nil {
		t.Fatal(e)
	}
	if e = reader.Close(); e != nil {
		t.Fatal(e)
	}
	intent, e := reopenRemovalMetadataFixture(parent, fence)
	if e != nil {
		t.Fatal(e)
	}
	if e = intent.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestDarwinRemovalIntentRefusesChangedBindingsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"compiled-core", "compiled-desktop", "missing-writer", "missing-runtime", "replaced-writer", "replaced-runtime", "displaced-history", "missing-history", "unknown-history", "changed-versions-parent"} {
		t.Run(kind, func(t *testing.T) {
			parent, fence, plan := publishedRemovalMetadataFixture(t)
			root := filepath.Join(parent, deploymentRoot)
			switch kind {
			case "compiled-core":
				fence.Target.Identity.PayloadSHA256 = strings.Repeat("f", 64)
			case "compiled-desktop":
				fence.DesktopRecordSHA256 = strings.Repeat("f", 64)
			case "missing-writer", "missing-runtime", "replaced-writer", "replaced-runtime":
				name, mode := deploymentLock, os.FileMode(0600)
				if strings.HasSuffix(kind, "runtime") {
					name, mode = runtimeLeaseName, 0644
				}
				target := filepath.Join(root, name)
				// Keep the old vnode alive so replacement cannot reuse its inode.
				if strings.HasPrefix(kind, "replaced") {
					old, e := os.Open(target)
					if e != nil {
						t.Fatal(e)
					}
					defer old.Close()
				}
				if e := os.Remove(target); e != nil {
					t.Fatal(e)
				} // Exact owned fixture file.
				if strings.HasPrefix(kind, "replaced") {
					if e := os.WriteFile(target, nil, mode); e != nil {
						t.Fatal(e)
					}
				}
			case "displaced-history":
				target := filepath.Join(root, fence.DisplacedRecord, deploymentRecord)
				raw, e := os.ReadFile(target)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(target, append(raw, ' '), 0644); e != nil {
					t.Fatal(e)
				}
			case "missing-history":
				for _, h := range plan.History {
					if h.Name == "state" {
						continue
					}
					if e := os.Rename(filepath.Join(root, h.Name), filepath.Join(parent, "owned-retained-history")); e != nil {
						t.Fatal(e)
					}
					break
				}
			case "unknown-history":
				if e := os.Mkdir(filepath.Join(root, ".record-"+strings.Repeat("f", 32)), 0755); e != nil {
					t.Fatal(e)
				}
			case "changed-versions-parent":
				if e := os.Rename(filepath.Join(root, "versions"), filepath.Join(parent, "owned-old-versions")); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(filepath.Join(root, "versions"), 0755); e != nil {
					t.Fatal(e)
				}
			}
			before, e := os.ReadDir(root)
			if e != nil {
				t.Fatal(e)
			}
			markerPath := filepath.Join(root, "state", removalFenceName)
			marker, e := os.ReadFile(markerPath)
			if e != nil {
				t.Fatal(e)
			}
			if intent, e := reopenRemovalMetadataFixture(parent, fence); e == nil {
				intent.Close()
				t.Fatal("changed removal binding accepted")
			}
			after, e := os.ReadDir(root)
			if e != nil || len(after) != len(before) {
				t.Fatal("failed reopen created or removed authority objects", e)
			}
			saved, e := os.ReadFile(markerPath)
			if e != nil || !bytes.Equal(saved, marker) {
				t.Fatal("failed reopen repaired intent", e)
			}
			for i := range before {
				if before[i].Name() != after[i].Name() {
					t.Fatal("failed reopen changed authority names")
				}
			}
		})
	}
}
