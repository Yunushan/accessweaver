//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"encoding/binary"
	"errors"
	"os"
	"regexp"
	"runtime"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

var desktopRecordFile = regexp.MustCompile(`^desktop-[a-f0-9]{64}\.json$`)

// Registrations are bounded immutable files installed by a separate Apple
// component below a protected parent. The component never owns core versions.
func readDesktopRegistrations() ([]desktopRecord, [][]byte, error) {
	parent, e := darwintrust.OpenRootDirectory(deploymentParent)
	if e != nil {
		return nil, nil, e
	}
	defer parent.Close()
	root, e := deploymentDirectory(parent, desktopRoot, 0, false)
	if darwintrust.IsReadAbsent(e) {
		return nil, nil, nil
	}
	if e != nil {
		return nil, nil, e
	}
	defer root.Close()
	entries, e := deploymentEntries(root, 0, 64)
	if e != nil {
		return nil, nil, e
	}
	records := []desktopRecord{}
	encoded := [][]byte{}
	for _, entry := range entries {
		if !desktopRecordFile.MatchString(entry.Name()) {
			return nil, nil, errors.New("unknown desktop registration object; preserve and inspect")
		}
		data, e := readDetachedDeploymentFile(root, entry.Name(), maxDesktopRecord)
		if e != nil {
			return nil, nil, e
		}
		if desktopRecordName(data) != entry.Name() {
			return nil, nil, errors.New("desktop registration file seal differs")
		}
		r, e := decodeDesktopRecord(data, runtime.GOARCH)
		if e != nil {
			return nil, nil, e
		}
		for _, old := range records {
			order, e := CompareVersions(r.Build.Version, old.Build.Version)
			if e != nil {
				return nil, nil, e
			}
			if order == 0 {
				return nil, nil, errors.New("ambiguous same-version desktop registrations; preserve and inspect")
			}
		}
		records = append(records, r)
		encoded = append(encoded, data)
	}
	if e = sameDeploymentEntry(parent, desktopRoot, root, 0); e != nil {
		return nil, nil, e
	}
	return records, encoded, nil
}
func verifyDesktopApplication(apps *os.File, r desktopRecord) error {
	app, e := directoryAt(apps, "AccessWeaver.app")
	if e != nil {
		return e
	}
	defer app.Close()
	if e = deploymentObject(app, true, 0, 0755); e != nil {
		return e
	}
	important, e := inspectBundleInventory(app, r.Manifest, nil, false)
	if e != nil {
		return e
	}
	b, e := decodeBuild(important["Contents/Resources/BUILD-INFO.json"], runtime.GOARCH)
	if e != nil {
		return e
	}
	if b != r.Build {
		return errors.New("public desktop build differs from protected registration")
	}
	if e = checkBundlePlist(important["Contents/Info.plist"], b.Version, desktopBundleID, desktopExecutable); e != nil {
		return e
	}
	image := important["Contents/MacOS/"+desktopExecutable]
	cpu := uint32(0x01000007)
	if runtime.GOARCH == "arm64" {
		cpu = 0x0100000c
	}
	if len(image) < 32 || binary.LittleEndian.Uint32(image) != 0xfeedfacf || binary.LittleEndian.Uint32(image[4:]) != cpu || binary.LittleEndian.Uint32(image[12:]) != 2 {
		return errors.New("public launcher native image differs")
	}
	return sameDeploymentEntry(apps, "AccessWeaver.app", app, 0)
}
func desktopApplicationCompatible(apps *os.File, records []desktopRecord) error {
	var st unix.Stat_t
	e := unix.Fstatat(int(apps.Fd()), "AccessWeaver.app", &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	app, e := directoryAt(apps, "AccessWeaver.app")
	if e != nil {
		return e
	}
	encoded, readErr := readPath(app, "Contents/Resources/BUILD-INFO.json", 16384)
	e = errors.Join(readErr, app.Close())
	if e != nil {
		return e
	}
	// This public self-description only filters candidates for full verification;
	// it supplies neither trust, a privileged executable nor an authority path.
	build, e := decodeBuild(encoded, runtime.GOARCH)
	if e != nil {
		return e
	}
	for _, r := range records {
		if r.Build == build {
			return verifyDesktopApplication(apps, r)
		}
	}
	return errors.New("legacy, changed or unregistered public app exists; explicit migration or repair is required")
}
func legacyReceiptsAbsent() error {
	receipts, e := darwintrust.OpenRootDirectory("/private/var/db/receipts")
	if e != nil {
		return e
	}
	defer receipts.Close()
	for _, name := range []string{BundleID + ".plist", BundleID + ".bom"} {
		var st unix.Stat_t
		e = unix.Fstatat(int(receipts.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if e == nil {
			return errors.New("legacy receipt exists; explicit migration is required")
		}
		if !errors.Is(e, unix.ENOENT) {
			return e
		}
	}
	return nil
}
func desktopCoreActive() error {
	parent, err := darwintrust.OpenRootDirectory(deploymentParent)
	if err != nil {
		return err
	}
	r := nativeRuntimeReads()
	lease, err := acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error {
		if _, _, err := r.readActiveRuntime(root, ""); err != nil {
			return err
		}
		if err := r.sameDeploymentEntry(parent, deploymentRoot, root, 0); err != nil {
			return err
		}
		return r.sameRuntimeFile(root, lease.file, 0)
	})
	if err != nil {
		return err
	}
	return r.finishLease(lease, nil)
}

// Apple Installer alone writes the public app/registration payloads. This
// fixed-path helper only verifies them; it never creates, deletes, executes or
// repairs any public application. A failed postinstall preserves actual state.
func DesktopPackageOperation(phase string) (DesktopPackageResult, error) {
	return desktopPackageOperation(phase, false)
}

// coordinated is reachable only after ProductPackageOperation validates both
// compiled core and public application seals. Standalone components remain strict.
func desktopPackageOperation(phase string, coordinated bool) (DesktopPackageResult, error) {
	var result DesktopPackageResult
	if phase != "preinstall" && phase != "postinstall" {
		return result, errors.New("unknown desktop package phase")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return result, errors.New("desktop package inspection requires root")
	}
	b, component, seal, e := compiledDesktopIdentity()
	if e != nil {
		return result, e
	}
	if b.Arch != runtime.GOARCH {
		return result, errors.New("desktop packaging helper is not native")
	}
	if e = legacyReceiptsAbsent(); e != nil {
		return result, e
	}
	apps, e := applications()
	if e != nil {
		return result, e
	}
	defer apps.Close()
	records, encoded, e := readDesktopRegistrations()
	if e != nil {
		return result, e
	}
	selected := -1
	for i, r := range records {
		order, e := CompareVersions(b.Version, r.Build.Version)
		if e != nil {
			return result, e
		}
		if order < 0 {
			return result, errors.New("desktop downgrade refused by retained registration")
		}
		matches := digest(encoded[i]) == seal
		if order == 0 && !matches {
			return result, errors.New("same-version desktop registration differs; preserve and inspect")
		}
		if matches {
			if r.Build != b {
				return result, errors.New("compiled desktop build differs from registered record")
			}
			selected = i
		}
	}
	if phase == "preinstall" {
		if e = desktopApplicationCompatible(apps, records); e != nil {
			return result, e
		}
		if component == "metadata" && selected < 0 && len(records) >= 64 {
			return result, errors.New("desktop registration capacity exhausted; preserve and inspect")
		}
	} else if selected < 0 {
		return result, errors.New("compiled desktop registration is missing after package copy")
	}
	if component == "application" {
		if !coordinated {
			if selected < 0 {
				return result, errors.New("install matching protected desktop metadata before the application component")
			}
			if e = desktopCoreActive(); e != nil {
				return result, e
			}
		}
		if phase == "postinstall" {
			if e = verifyDesktopApplication(apps, records[selected]); e != nil {
				return result, e
			}
		}
	}
	// The JSON result records only completed read-only verification, not what
	// Apple Installer might have copied before invoking this process.
	result = DesktopPackageResult{SchemaVersion: 1, Component: component, Phase: phase, Version: b.Version, RecordSHA256: seal, PublicApplicationVerified: component == "application" && phase == "postinstall"}
	return result, nil
}
