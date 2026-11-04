//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

type removalIncomingEntry struct {
	Identity    deploymentIdentity `json:"identity"`
	Device      uint64             `json:"device"`
	Inode       uint64             `json:"inode"`
	PathsSHA256 string             `json:"pathsSHA256"`
	paths       []string
}
type removalIncomingSnapshot struct {
	Device  uint64                 `json:"device"`
	Inode   uint64                 `json:"inode"`
	Entries []removalIncomingEntry `json:"entries"`
}

func (s *deploymentStore) removalIncomingInventory(slots []deploymentSlot) (removalIncomingSnapshot, error) {
	var result removalIncomingSnapshot
	known := map[string]deploymentIdentity{}
	for _, slot := range slots {
		if old, ok := known[slot.Identity.ManifestSHA256]; ok && old != slot.Identity {
			return result, errors.New("conflicting incoming identity in protected history")
		}
		known[slot.Identity.ManifestSHA256] = slot.Identity
	}
	incoming, e := deploymentDirectory(s.parent, deploymentIncoming, 0, false)
	if e != nil {
		return result, e
	}
	defer incoming.Close()
	info, e := incoming.Stat()
	if e != nil {
		return result, e
	}
	st := info.Sys().(*syscall.Stat_t)
	result.Device, result.Inode = uint64(st.Dev), st.Ino
	entries, e := deploymentEntries(incoming, 0, maxRetainedDeployments)
	if e != nil {
		return result, e
	}
	if len(entries) != len(known) {
		return result, errors.New("unknown or missing incoming product payload; preserve and inspect")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		identity, ok := known[entry.Name()]
		if !ok {
			return result, errors.New("unrecorded incoming product payload; preserve and inspect")
		}
		stage, e := deploymentDirectory(incoming, entry.Name(), 0, false)
		if e != nil {
			return result, e
		}
		app, encoded, sbom, embedded, openErr := openDeploymentBundle(stage)
		if openErr != nil {
			return result, errors.Join(openErr, stage.Close())
		}
		m, _, verifyErr := verifyDeploymentInventory(app, identity, encoded, embedded, sbom)
		info, statErr := stage.Stat()
		sameErr := sameDeploymentEntry(incoming, entry.Name(), stage, 0)
		if e = errors.Join(verifyErr, statErr, sameErr, app.Close(), stage.Close()); e != nil {
			return result, e
		}
		paths := removalBundleReceiptPaths(m, embedded, true)
		raw, _ := json.Marshal(paths)
		st := info.Sys().(*syscall.Stat_t)
		result.Entries = append(result.Entries, removalIncomingEntry{identity, uint64(st.Dev), st.Ino, digest(raw), paths})
	}
	if e = sameDeploymentEntry(s.parent, deploymentIncoming, incoming, 0); e != nil {
		return result, e
	}
	return result, nil
}

type removalReceiptFile struct {
	Name    string `json:"name"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Bytes   int64  `json:"bytes"`
	MtimeNs int64  `json:"mtimeNs"`
	CtimeNs int64  `json:"ctimeNs"`
	SHA256  string `json:"sha256"`
}
type removalReceiptSnapshot struct {
	Device         uint64               `json:"device"`
	Inode          uint64               `json:"inode"`
	Files          []removalReceiptFile `json:"files"`
	MetadataSHA256 []string             `json:"metadataSHA256"`
	PathsSHA256    []string             `json:"pathsSHA256"`
}
type removalMetadataOutput struct {
	data    []byte
	maximum int
	cancel  context.CancelFunc
}

func (w *removalMetadataOutput) Write(data []byte) (int, error) {
	if len(data) > w.maximum-len(w.data) {
		w.cancel()
		return 0, errors.New("removal receipt query output exceeds budget")
	}
	w.data = append(w.data, data...)
	return len(data), nil
}
func queryRemovalReceipt(ctx context.Context, operation, id string) ([]byte, error) {
	if !validRemovalReceiptID(id) || (operation != "--pkg-info" && operation != "--files") {
		return nil, errors.New("invalid fixed receipt query")
	}
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, "/usr/sbin/pkgutil", operation, id)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
	cmd.WaitDelay = 300 * time.Millisecond
	maximum := 65536
	if operation == "--files" {
		maximum = maxRemovalReceiptPathsBytes
	}
	out := removalMetadataOutput{maximum: maximum, cancel: cancel}
	stderr := removalMetadataOutput{maximum: 65536, cancel: cancel}
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if e := cmd.Run(); e != nil {
		return nil, errors.New("native removal receipt query failed")
	}
	return out.data, nil
}
func removalReceiptsInventory(ctx context.Context, identity deploymentIdentity, records []desktopRecord, encoded [][]byte, selected int, incoming removalIncomingSnapshot) (removalReceiptSnapshot, error) {
	var result removalReceiptSnapshot
	if len(records) != len(encoded) || selected < 0 || selected >= len(records) {
		return result, errors.New("invalid protected removal registration selection")
	}
	currentPaths := []string(nil)
	for _, entry := range incoming.Entries {
		if entry.Identity == identity {
			currentPaths = entry.paths
		}
	}
	if len(currentPaths) == 0 {
		return result, errors.New("active incoming receipt inventory is absent")
	}
	expected := []removalReceiptExpectation{{removalCoreReceiptID, identity.Version, deploymentParent + "/" + deploymentIncoming + "/" + identity.ManifestSHA256, currentPaths}, {desktopBundleID, records[selected].Build.Version, "/Applications", removalBundleReceiptPaths(records[selected].Manifest, false, false)}}
	for i, record := range records {
		expected = append(expected, removalReceiptExpectation{desktopBundleID + ".registration." + digest(encoded[i]), record.Build.Version, deploymentParent + "/" + desktopRoot, []string{desktopRecordName(encoded[i])}})
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i].ID < expected[j].ID })
	allowed := map[string]bool{}
	for _, r := range expected {
		for _, suffix := range []string{".plist", ".bom"} {
			allowed[r.ID+suffix] = true
		}
	}
	root, e := darwintrust.OpenRootDirectory("/private/var/db/receipts")
	if e != nil {
		return result, e
	}
	defer root.Close()
	info, e := root.Stat()
	if e != nil {
		return result, e
	}
	st := info.Sys().(*syscall.Stat_t)
	result.Device, result.Inode = uint64(st.Dev), st.Ino
	entries, e := deploymentEntries(root, 0, 16384)
	if e != nil {
		return result, e
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(strings.ToLower(name), BundleID+".") {
			if !allowed[name] {
				return result, errors.New("unknown product receipt; preserve and inspect")
			}
			seen[name] = true
		}
	}
	if len(seen) != len(allowed) {
		return result, errors.New("expected product receipt is missing")
	}
	for _, r := range expected {
		for _, suffix := range []string{".plist", ".bom"} {
			name := r.ID + suffix
			raw, st, e := readAt(root, name, 4<<20)
			if e != nil {
				return result, e
			}
			if len(raw) == 0 || st.Mode&07777 != 0644 {
				return result, errors.New("product receipt file mode or size differs")
			}
			result.Files = append(result.Files, removalReceiptFile{name, uint64(st.Dev), st.Ino, int64(len(raw)), st.Mtimespec.Sec*1e9 + st.Mtimespec.Nsec, st.Ctimespec.Sec*1e9 + st.Ctimespec.Nsec, digest(raw)})
		}
		metadata, e := queryRemovalReceipt(ctx, "--pkg-info", r.ID)
		if e != nil {
			return result, e
		}
		if e = checkRemovalReceiptMetadata(metadata, r); e != nil {
			return result, e
		}
		files, e := queryRemovalReceipt(ctx, "--files", r.ID)
		if e != nil {
			return result, e
		}
		paths, e := checkRemovalReceiptPaths(files, r.Paths)
		if e != nil {
			return result, e
		}
		raw, _ := json.Marshal(paths)
		result.MetadataSHA256 = append(result.MetadataSHA256, digest(metadata))
		result.PathsSHA256 = append(result.PathsSHA256, digest(raw))
	}
	return result, nil
}
