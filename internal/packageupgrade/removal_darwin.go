//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"syscall"
)

type removalRecord struct {
	Name   string `json:"name"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	SHA256 string `json:"sha256"`
}
type removalCoreSnapshot struct {
	Records []removalRecord  `json:"records"`
	Slots   []deploymentSlot `json:"slots"`
}

func (s *deploymentStore) removalCore(identity deploymentIdentity) (removalCoreSnapshot, error) {
	var snapshot removalCoreSnapshot
	if e := s.checkRoot(); e != nil {
		return snapshot, e
	}
	if e := sameDeploymentEntry(s.root, "state", s.current, s.owner); e != nil {
		return snapshot, e
	}
	entries, e := deploymentEntries(s.root, s.owner, maxRetainedRecords+4)
	if e != nil {
		return snapshot, e
	}
	history := []deploymentState{}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if name == deploymentLock || name == runtimeLeaseName || name == "versions" {
			continue
		}
		if name != "state" && !recordName.MatchString(name) {
			return snapshot, errors.New("unknown removal authority object; preserve and inspect")
		}
		dir, e := deploymentDirectory(s.root, name, s.owner, false)
		if e != nil {
			return snapshot, e
		}
		data, readErr := s.readRecord(dir)
		info, statErr := dir.Stat()
		sameErr := sameDeploymentEntry(s.root, name, dir, s.owner)
		if e = errors.Join(readErr, statErr, sameErr, dir.Close()); e != nil {
			return snapshot, e
		}
		state, e := decodeDeployment(data)
		if e != nil {
			return snapshot, e
		}
		if name == "state" {
			if !bytes.Equal(data, s.encoded) {
				return snapshot, errors.New("removal current record changed")
			}
		} else {
			history = append(history, state)
		}
		st := info.Sys().(*syscall.Stat_t)
		snapshot.Records = append(snapshot.Records, removalRecord{name, uint64(st.Dev), st.Ino, digest(data)})
	}
	slots, e := removalSlots(s.state, identity, history)
	if e != nil {
		return snapshot, e
	}
	actual, e := deploymentEntries(s.versions, s.owner, maxRetainedDeployments)
	if e != nil {
		return snapshot, e
	}
	if len(actual) != len(slots) {
		return snapshot, errors.New("unknown or missing retained removal copy; preserve and inspect")
	}
	known := map[string]deploymentSlot{}
	for _, slot := range slots {
		known[slot.ID] = slot
	}
	for _, entry := range actual {
		slot, ok := known[entry.Name()]
		if !ok {
			return snapshot, errors.New("unrecorded retained removal copy; preserve and inspect")
		}
		if e := s.verifySlot(slot); e != nil {
			return snapshot, e
		}
	}
	snapshot.Slots = slots
	return snapshot, nil
}

// InspectProductRemoval verifies a fixed, bounded subset needed by the future
// uninstall transaction. It never creates a record, deactivates a core, removes
// files, forgets receipts or accesses user profiles. Only an externally trusted,
// separately staged helper with both exact compiled seals can inspect it.
func InspectProductRemoval() (result ProductRemovalInspection, err error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return result, errors.New("product removal inspection requires root")
	}
	identity, e := compiledProductIdentity()
	if e != nil {
		return result, e
	}
	build, _, seal, e := compiledDesktopIdentity()
	if e != nil {
		return result, e
	}
	result = ProductRemovalInspection{SchemaVersion: 1, Operation: "inspect-product-removal", State: "refused", Version: identity.Version, ManifestSHA256: identity.ManifestSHA256, PayloadSHA256: identity.PayloadSHA256, DesktopRecordSHA256: seal, InventoryScope: "core-history-public-app-registrations"}
	defer func() {
		if err != nil {
			result.State = "refused"
			result.RetainedCoreCopies, result.RetainedStateRecords, result.DesktopRegistrations = 0, 0, 0
			result.InventorySHA256 = ""
		}
	}()
	if e = legacyReceiptsAbsent(); e != nil {
		return result, e
	}
	s, e := openDeployment(false)
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	result.Generation = s.state.Generation
	core, e := s.removalCore(identity)
	if e != nil {
		return result, e
	}
	registry, e := deploymentDirectory(s.parent, desktopRoot, 0, false)
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, registry.Close()) }()
	records, encoded, e := readDesktopRegistrations()
	if e != nil {
		return result, e
	}
	selected := -1
	for i, record := range records {
		order, e := CompareVersions(record.Build.Version, build.Version)
		if e != nil {
			return result, e
		}
		if order > 0 {
			return result, errors.New("removal desktop history is newer than the compiled release")
		}
		if digest(encoded[i]) == seal && record.Build == build {
			selected = i
		}
	}
	if selected < 0 {
		return result, errors.New("matching compiled removal desktop registration is absent")
	}
	apps, e := applications()
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, apps.Close()) }()
	app, e := directoryAt(apps, "AccessWeaver.app")
	if e != nil {
		return result, e
	}
	defer func() { err = errors.Join(err, app.Close()) }()
	if e = verifyDesktopApplication(apps, records[selected]); e != nil {
		return result, e
	}
	appInfo, e := app.Stat()
	if e != nil {
		return result, e
	}
	// The public parent can be writable by administrators; bind the app identity
	// held across inspection, not just an equal self-description in a new object.
	if e = sameDeploymentEntry(apps, "AccessWeaver.app", app, 0); e != nil {
		return result, e
	}
	_, again, e := readDesktopRegistrations()
	if e != nil {
		return result, e
	}
	canonical := func(values [][]byte) []string {
		out := make([]string, 0, len(values))
		for _, raw := range values {
			out = append(out, digest(raw))
		}
		sort.Strings(out)
		return out
	}
	hashes, againHashes := canonical(encoded), canonical(again)
	before, _ := json.Marshal(hashes)
	after, _ := json.Marshal(againHashes)
	if !bytes.Equal(before, after) {
		return result, errors.New("removal desktop registrations changed")
	}
	if e = sameDeploymentEntry(s.parent, desktopRoot, registry, 0); e != nil {
		return result, e
	}
	checked, e := s.removalCore(identity)
	if e != nil {
		return result, e
	}
	before, e = json.Marshal(core)
	if e != nil {
		return result, e
	}
	after, e = json.Marshal(checked)
	if e != nil {
		return result, e
	}
	if !bytes.Equal(before, after) {
		return result, errors.New("removal core inventory changed")
	}
	if e = verifyDesktopApplication(apps, records[selected]); e != nil {
		return result, e
	}
	if e = sameDeploymentEntry(apps, "AccessWeaver.app", app, 0); e != nil {
		return result, e
	}
	if e = s.checkRoot(); e != nil {
		return result, e
	}
	st := appInfo.Sys().(*syscall.Stat_t)
	fingerprint, e := json.Marshal(struct {
		Generation   uint64              `json:"generation"`
		Core         removalCoreSnapshot `json:"core"`
		Desktop      []string            `json:"desktop"`
		PublicDevice uint64              `json:"publicDevice"`
		PublicInode  uint64              `json:"publicInode"`
	}{s.state.Generation, core, hashes, uint64(st.Dev), st.Ino})
	if e != nil {
		return result, e
	}
	result.State = "inspected"
	result.RetainedCoreCopies = len(core.Slots)
	result.RetainedStateRecords = len(core.Records)
	result.DesktopRegistrations = len(records)
	result.InventorySHA256 = digest(fingerprint)
	return result, nil
}
