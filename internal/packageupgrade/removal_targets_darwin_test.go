//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

type ownedRemovalTargetFixture struct {
	base                                                                                string
	store                                                                               *deploymentStore
	intent                                                                              *removalIntentStore
	publicFile, publicRoot, incomingParent, incomingRoot, registrationRoot, receiptRoot string
}

func (f *ownedRemovalTargetFixture) openParent(kind string) (*os.File, error) {
	s := f.store
	switch kind {
	case "core":
		return deploymentDirectory(s.root, "versions", 0, false)
	case "registrations":
		fd, e := unix.Openat(int(s.parent.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		return os.NewFile(uintptr(fd), "owned-registration-parent"), nil
	case "incoming":
		return deploymentDirectory(s.parent, "owned-incoming", 0, false)
	case "receipts":
		return deploymentDirectory(s.parent, "owned-db", 0, false)
	case "public":
		fd, e := unix.Openat(int(s.parent.Fd()), "owned-applications", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		file := os.NewFile(uintptr(fd), "owned-Applications-parent")
		info, e := file.Stat()
		if e == nil {
			st := info.Sys().(*syscall.Stat_t)
			if st.Uid != 0 || st.Gid != 80 || info.Mode().Perm() != 0775 {
				e = errors.New("owned Applications fixture protection differs")
			}
		}
		if e == nil {
			e = errors.Join(darwintrust.CheckPersistent(file), darwintrust.CheckReadOnlyACL(file))
		}
		if e != nil {
			return nil, errors.Join(e, file.Close())
		}
		return file, nil
	default:
		return nil, errors.New("unknown owned fixture role")
	}
}
func (f *ownedRemovalTargetFixture) resolve(kind string) (removalTargetParent, error) {
	file, e := f.openParent(kind)
	if e != nil {
		return removalTargetParent{}, e
	}
	return removalTargetParent{file, true, func() error {
		return sameRemovalTargetParent(file, func() (*os.File, error) { return f.openParent(kind) })
	}}, nil
}

// Every tree is real owned filesystem data. Synthetic non-code payloads test
// exact saved-object relationships without pretending to be a shipping app.
func newOwnedRemovalTargetFixture(t *testing.T, privateBase string) *ownedRemovalTargetFixture {
	t.Helper()
	base, e := os.MkdirTemp(privateBase, "targets-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(base, 0, 0); e != nil {
		t.Fatal(e)
	}
	s := deploymentFixtureStore(t, base, nil)
	f := &ownedRemovalTargetFixture{base: base, store: s}
	mkdir := func(name string) {
		t.Helper()
		if e := os.Mkdir(name, 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.Chown(name, 0, 0); e != nil {
			t.Fatal(e)
		}
	}
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		if e := os.WriteFile(name, data, mode); e != nil {
			t.Fatal(e)
		}
		if e := os.Chown(name, 0, 0); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(name, mode); e != nil {
			t.Fatal(e)
		}
	}
	slot := deploymentFixtureSlot(1, "0.1.1-alpha")
	corePath := filepath.Join(base, deploymentRoot, "versions", slot.ID)
	mkdir(corePath)
	write(filepath.Join(corePath, "owned-core"), []byte("owned core bytes"), 0644)
	info, e := os.Stat(corePath)
	if e != nil {
		t.Fatal(e)
	}
	st := info.Sys().(*syscall.Stat_t)
	slot.Device = int64(st.Dev)
	slot.Inode = st.Ino
	state := deploymentState{SchemaVersion: 1, Generation: 1, HighWaterVersion: slot.Identity.Version, Active: slot, Pending: []deploymentPending{}}
	if _, e = s.commit(state); e != nil {
		t.Fatal(e)
	}
	plan := removalMetadataPlanFixture(t, s)
	plan.Roots = []removalPlanRoot{}
	f.incomingParent = filepath.Join(base, "owned-incoming")
	mkdir(f.incomingParent)
	f.incomingRoot = filepath.Join(f.incomingParent, slot.Identity.ManifestSHA256)
	mkdir(f.incomingRoot)
	write(filepath.Join(f.incomingRoot, "owned-input"), []byte("owned incoming bytes"), 0644)
	apps := filepath.Join(base, "owned-applications")
	mkdir(apps)
	if e = os.Chown(apps, 0, 80); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(apps, 0775); e != nil {
		t.Fatal(e)
	}
	f.publicRoot = filepath.Join(apps, "AccessWeaver.app")
	mkdir(f.publicRoot)
	f.publicFile = filepath.Join(f.publicRoot, "owned-public")
	write(f.publicFile, []byte("owned public bytes"), 0644)
	f.registrationRoot = filepath.Join(base, desktopRoot)
	mkdir(f.registrationRoot)
	registration := []byte("owned synthetic registration")
	seal := removalDigest(registration)
	plan.DesktopRecordSHA256 = seal
	write(filepath.Join(f.registrationRoot, "desktop-"+seal+".json"), registration, 0644)
	db := filepath.Join(base, "owned-db")
	mkdir(db)
	f.receiptRoot = filepath.Join(db, "receipts")
	mkdir(f.receiptRoot)
	receiptData := map[string][]byte{}
	for _, id := range []string{removalCoreReceiptID, desktopBundleID, desktopBundleID + ".registration." + seal} {
		for _, ext := range []string{".bom", ".plist"} {
			name := id + ext
			receiptData[name] = []byte("owned receipt " + name)
			write(filepath.Join(f.receiptRoot, name), receiptData[name], 0644)
		}
	}
	write(filepath.Join(f.receiptRoot, "unrelated-private.plist"), []byte("unrelated private bytes"), 0600)
	write(filepath.Join(base, "private-profile"), []byte("retained private profile"), 0600)
	for _, role := range []string{"core", "incoming", "public", "registrations", "receipts"} {
		parent, e := f.openParent(role)
		if e != nil {
			t.Fatal(e)
		}
		key := ""
		identity := deploymentIdentity{}
		data := map[string][]byte{}
		switch role {
		case "core":
			key = slot.ID
			identity = slot.Identity
			data["owned-core"] = []byte("owned core bytes")
		case "incoming":
			key = slot.Identity.ManifestSHA256
			identity = slot.Identity
			data["owned-input"] = []byte("owned incoming bytes")
		case "public":
			key = "AccessWeaver.app"
			data["owned-public"] = []byte("owned public bytes")
		case "registrations":
			key = desktopRoot
			data["desktop-"+seal+".json"] = registration
		case "receipts":
			key = "receipts"
			data = receiptData
		}
		root, e := deploymentDirectory(parent, key, 0, false)
		if e != nil {
			t.Fatal(e)
		}
		catalog := removalCatalog{}
		for name, raw := range data {
			catalog[name] = removalCatalogEntry{file: File{name, int64(len(raw)), removalDigest(raw), "0644"}}
		}
		tree, captureErr := captureRemovalTree(context.Background(), parent, root, role, key, identity, catalog)
		if e = errors.Join(captureErr, root.Close(), parent.Close()); e != nil {
			t.Fatal(e)
		}
		plan.Roots = append(plan.Roots, tree)
	}
	sort.Slice(plan.Roots, func(i, j int) bool {
		return plan.Roots[i].Kind+"\x00"+plan.Roots[i].Key < plan.Roots[j].Kind+"\x00"+plan.Roots[j].Key
	})
	fence, _, e := newRemovalFence(s.state, seal, strings.Repeat("e", 64), plan)
	if e != nil {
		t.Fatal(e)
	}
	if published, e := s.publishRemovalFence(fence, plan); !published || e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	parent, e := os.Open(base)
	if e != nil {
		t.Fatal(e)
	}
	f.intent, e = openRemovalIntentAt(parent, 0, slot.Identity, seal)
	if e != nil {
		t.Fatal(e)
	}
	f.store = f.intent.store
	t.Cleanup(func() { f.intent.Close() })
	return f
}
func exerciseOwnedRemovalTargetVerification(t *testing.T, privateBase string) {
	t.Helper()
	for _, kind := range []string{"complete", "cancelled", "missing-root", "missing-file", "changed-file", "restored-bytes", "replaced-file", "file-alias", "root-alias", "hardlink", "file-mode", "parent-replaced", "extra-core", "extra-incoming", "extra-registration", "extra-receipt"} {
		passed := t.Run("intact-targets-"+kind, func(t *testing.T) {
			f := newOwnedRemovalTargetFixture(t, privateBase)
			baseline, e := f.intent.verifyIntactTargetsUsing(context.Background(), f.resolve)
			if e != nil || baseline.roots != 5 || baseline.files != 10 || baseline.directories != 5 || baseline.planSHA256 != f.intent.fence.PlanSHA256 {
				t.Fatal("owned target baseline differs", baseline, e)
			}
			profile, e := os.ReadFile(filepath.Join(f.base, "private-profile"))
			if e != nil {
				t.Fatal(e)
			}
			unrelated, e := os.ReadFile(filepath.Join(f.receiptRoot, "unrelated-private.plist"))
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			switch kind {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing-root":
				e = os.Rename(f.incomingRoot, filepath.Join(f.base, "owned-parked-input"))
			case "missing-file":
				e = os.Rename(f.publicFile, filepath.Join(f.base, "owned-parked-file"))
			case "changed-file":
				e = os.WriteFile(f.publicFile, []byte("changed public bytes"), 0644)
			case "restored-bytes":
				raw, readErr := os.ReadFile(f.publicFile)
				if readErr != nil {
					t.Fatal(readErr)
				}
				info, statErr := os.Stat(f.publicFile)
				if statErr != nil {
					t.Fatal(statErr)
				}
				if e = os.WriteFile(f.publicFile, []byte("changed"), 0644); e == nil {
					e = os.WriteFile(f.publicFile, raw, 0644)
				}
				if e == nil {
					e = os.Chtimes(f.publicFile, info.ModTime(), info.ModTime().Add(2*time.Second))
				}
			case "replaced-file":
				raw, readErr := os.ReadFile(f.publicFile)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if e = os.Rename(f.publicFile, filepath.Join(f.base, "owned-original-file")); e == nil {
					e = os.WriteFile(f.publicFile, raw, 0644)
				}
			case "file-alias":
				backup := filepath.Join(f.base, "owned-alias-target")
				if e = os.Rename(f.publicFile, backup); e == nil {
					e = os.Symlink(backup, f.publicFile)
				}
			case "root-alias":
				backup := filepath.Join(f.base, "owned-alias-root")
				if e = os.Rename(f.publicRoot, backup); e == nil {
					e = os.Symlink(backup, f.publicRoot)
				}
			case "hardlink":
				e = os.Link(f.publicFile, filepath.Join(f.base, "owned-link"))
			case "file-mode":
				e = os.Chmod(f.publicFile, 0664)
			case "parent-replaced":
				if e = os.Rename(f.incomingParent, filepath.Join(f.base, "owned-original-parent")); e == nil {
					e = os.Mkdir(f.incomingParent, 0755)
				}
			case "extra-core":
				e = os.Mkdir(filepath.Join(f.base, deploymentRoot, "versions", strings.Repeat("f", 32)), 0755)
			case "extra-incoming":
				e = os.Mkdir(filepath.Join(f.incomingParent, strings.Repeat("f", 64)), 0755)
			case "extra-registration":
				e = os.WriteFile(filepath.Join(f.registrationRoot, "unknown.json"), []byte("preserve"), 0644)
			case "extra-receipt":
				e = os.WriteFile(filepath.Join(f.receiptRoot, BundleID+".unknown.plist"), []byte("preserve"), 0644)
			}
			if e != nil {
				t.Fatal(e)
			}
			beforeVerification := ownedRemovalTargetSnapshot(t, f.base)
			observed, e := f.intent.verifyIntactTargetsUsing(ctx, f.resolve)
			if kind == "complete" {
				if e != nil || observed != baseline {
					t.Fatal("repeat target verification differs", observed, e)
				}
			} else if e == nil || observed != (removalTargetVerification{}) {
				t.Fatal("unsafe or partial verification accepted", observed, e)
			}
			if afterVerification := ownedRemovalTargetSnapshot(t, f.base); !bytes.Equal(beforeVerification, afterVerification) {
				t.Fatal("target verification changed owned fixture data or metadata")
			}
			saved, e := os.ReadFile(filepath.Join(f.base, "private-profile"))
			if e != nil || !bytes.Equal(saved, profile) {
				t.Fatal("private profile changed", e)
			}
			saved, e = os.ReadFile(filepath.Join(f.receiptRoot, "unrelated-private.plist"))
			if e != nil || !bytes.Equal(saved, unrelated) {
				t.Fatal("unrelated receipt bytes changed", e)
			}
			if e = f.intent.Close(); e != nil {
				t.Fatal(e)
			}
		})
		if !passed {
			t.Fatalf("owned intact-target case failed: %s", kind)
		}
	}
}

// WalkDir never follows fixture symlinks. The observer hashes only data created
// under this private owned capsule, excluding access times changed by reads.
func ownedRemovalTargetSnapshot(t *testing.T, root string) []byte {
	t.Helper()
	values := map[string]string{}
	e := filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, e := os.Lstat(name)
		if e != nil {
			return e
		}
		st := info.Sys().(*syscall.Stat_t)
		payload := ""
		if info.Mode().IsRegular() {
			data, e := os.ReadFile(name)
			if e != nil {
				return e
			}
			payload = removalDigest(data)
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, e := os.Readlink(name)
			if e != nil {
				return e
			}
			payload = removalDigest([]byte(target))
		} else if !info.IsDir() {
			return errors.New("unexpected owned fixture object")
		}
		relative, e := filepath.Rel(root, name)
		if e != nil {
			return e
		}
		values[relative] = fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%s", st.Dev, st.Ino, st.Mode, st.Uid, st.Gid, st.Nlink, st.Size, st.Mtimespec.Sec*1e9+st.Mtimespec.Nsec, st.Ctimespec.Sec*1e9+st.Ctimespec.Nsec, st.Flags, payload)
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
