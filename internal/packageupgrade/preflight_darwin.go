//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

func sameState(a, b syscall.Stat_t) bool { a.Atimespec = b.Atimespec; return a == b }

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func checkGroup(file *os.File) error {
	info, e := file.Stat()
	if e != nil {
		return e
	}
	if info.Sys().(*syscall.Stat_t).Gid != 0 {
		return errors.New("installed object is not root:wheel")
	}
	return nil
}
func readAt(parent *os.File, name string, limit int64) ([]byte, syscall.Stat_t, error) {
	return nativeRuntimeReads().readAt(parent, name, limit)
}
func (r runtimeReadOps) readAt(parent *os.File, name string, limit int64) (payload []byte, identity syscall.Stat_t, failure error) {
	var zero syscall.Stat_t
	file, e := darwintrust.OpenRegularAt(parent, name, 0)
	if e != nil {
		return nil, zero, e
	}
	defer func() {
		failure = r.finish(file, failure)
		if failure != nil {
			payload = nil
			identity = zero
		}
	}()
	if e = checkGroup(file); e != nil {
		return nil, zero, e
	}
	info, e := file.Stat()
	if e != nil {
		return nil, zero, e
	}
	before := *info.Sys().(*syscall.Stat_t)
	if info.Size() < 0 || info.Size() > limit {
		return nil, zero, errors.New("installed file exceeds read limit")
	}
	data, e := io.ReadAll(io.LimitReader(file, limit+1))
	if e != nil {
		return nil, zero, e
	}
	after, e := darwintrust.Check(file, false, 0)
	if e != nil {
		return nil, zero, e
	}
	if int64(len(data)) != info.Size() || !sameState(before, *after.Sys().(*syscall.Stat_t)) {
		return nil, zero, errors.New("installed file changed while reading")
	}
	return data, before, nil
}
func directoryAt(parent *os.File, name string) (*os.File, error) {
	return nativeRuntimeReads().directoryAt(parent, name)
}
func (r runtimeReadOps) directoryAt(parent *os.File, name string) (*os.File, error) {
	f, e := darwintrust.OpenDirectoryAt(parent, name, 0)
	if e != nil {
		return nil, e
	}
	if e = checkGroup(f); e != nil {
		return nil, r.finish(f, e)
	}
	return f, nil
}
func readPath(root *os.File, name string, limit int64) ([]byte, error) {
	return nativeRuntimeReads().readPath(root, name, limit)
}
func (r runtimeReadOps) readPath(root *os.File, name string, limit int64) (payload []byte, failure error) {
	parts := strings.Split(name, "/")
	current := root
	if len(parts) > 1 {
		var err error
		current, err = r.subdirectory(root, strings.Join(parts[:len(parts)-1], "/"))
		if err != nil {
			return nil, err
		}
		defer func() {
			failure = r.finish(current, failure)
			if failure != nil {
				payload = nil
			}
		}()
	}
	data, _, err := r.readAt(current, parts[len(parts)-1], limit)
	return data, err
}

// Only the fixed /Applications container admits its normal admin group write
// bit. The held bundle and every descendant still use the strict root:wheel
// owner/mode/ACL/APFS contract. This read-only exception is not a mutation grant.
func applications() (*os.File, error) {
	root, e := darwintrust.OpenRootDirectory("/")
	if e != nil {
		return nil, e
	}
	defer root.Close()
	fd, e := unix.Openat(int(root.Fd()), "Applications", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "/Applications")
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || st.Uid != 0 || (st.Gid != 0 && st.Gid != 80) || (info.Mode().Perm() != 0755 && info.Mode().Perm() != 0775) || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		f.Close()
		return nil, errors.New("unsupported Applications container protection")
	}
	if e = darwintrust.CheckPersistent(f); e == nil {
		e = darwintrust.CheckReadOnlyACL(f)
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func inspectBundle(root *os.File, m Manifest, encoded []byte) (map[string][]byte, error) {
	return inspectBundleInventory(root, m, encoded, true)
}

// Detached inventories cover every app file, including code-signature resources.
// Only the legacy reader admits the embedded inventory as an excluded file.
func inspectBundleInventory(root *os.File, m Manifest, encoded []byte, embedded bool) (map[string][]byte, error) {
	return nativeRuntimeReads().inspectBundleInventory(root, m, encoded, embedded)
}
func (r runtimeReadOps) inspectBundleInventory(root *os.File, m Manifest, encoded []byte, embedded bool) (map[string][]byte, error) {
	if embedded && m.SchemaVersion != 1 {
		return nil, errors.New("embedded manifest schema differs")
	}
	files := map[string]File{}
	dirs := map[string]bool{}
	seen := map[string]bool{}
	important := map[string][]byte{}
	for _, f := range m.Files {
		files[f.Path] = f
	}
	for _, d := range m.Directories {
		dirs[d.Path] = true
	}
	if embedded {
		files[ManifestName] = File{ManifestName, int64(len(encoded)), digest(encoded), "0644"}
	}
	count := 0
	total := int64(0)
	var walk func(*os.File, string, int) error
	walk = func(parent *os.File, prefix string, depth int) error {
		if depth > 32 {
			return errors.New("bundle exceeds depth limit")
		}
		entries, e := parent.ReadDir(MaxFiles + 1)
		if e != nil && e != io.EOF {
			return e
		}
		if len(entries) > MaxFiles {
			return errors.New("bundle exceeds inventory limit")
		}
		for _, entry := range entries {
			count++
			if count > MaxFiles {
				return errors.New("bundle exceeds inventory limit")
			}
			name := entry.Name()
			relative := prefix + name
			if !validPath(relative) || seen[relative] {
				return errors.New("invalid bundle inventory path")
			}
			seen[relative] = true
			if dirs[relative] {
				next, e := r.directoryAt(parent, name)
				if e != nil {
					return e
				}
				info, e := next.Stat()
				if e == nil && info.Mode().Perm() != 0755 {
					e = errors.New("bundle directory mode differs")
				}
				if e == nil {
					e = walk(next, relative+"/", depth+1)
				}
				e = r.finish(next, e)
				if e != nil {
					return e
				}
				continue
			}
			record, ok := files[relative]
			if !ok {
				return errors.New("unexpected installed bundle object")
			}
			data, st, e := r.readAt(parent, name, 64<<20)
			if e != nil {
				return e
			}
			total += int64(len(data))
			if total > MaxBytes+2<<20 {
				return errors.New("bundle exceeds byte budget")
			}
			mode := uint16(0644)
			if record.Mode == "0755" {
				mode = 0755
			}
			if st.Mode&07777 != mode || int64(len(data)) != record.Bytes || digest(data) != record.SHA256 {
				return errors.New("installed file differs from manifest")
			}
			switch relative {
			case "Contents/Info.plist", "Contents/Resources/BUILD-INFO.json", "Contents/MacOS/accessweaver", "Contents/MacOS/accessweaver-launcher":
				important[relative] = data
			}
		}
		return nil
	}
	if e := walk(root, "", 0); e != nil {
		return nil, e
	}
	if len(seen) != len(files)+len(dirs) {
		return nil, errors.New("installed bundle is incomplete")
	}
	return important, nil
}

type plistNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr  `xml:",any,attr"`
	Children []plistNode `xml:",any"`
	Text     string      `xml:",chardata"`
}

func checkPlist(data []byte, releaseVersion string) error {
	return checkBundlePlist(data, releaseVersion, BundleID, "accessweaver")
}
func checkBundlePlist(data []byte, releaseVersion, identifier, executable string) error {
	if len(data) > 1<<20 || bytes.Contains(data, []byte{0}) || bytes.Contains(bytes.ToUpper(data), []byte("<!ENTITY")) {
		return errors.New("unsupported plist encoding/extent")
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, count, roots := 0, 0, 0
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		count++
		switch node := t.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			if roots > 1 || node.Name.Space != "" {
				return errors.New("unsupported plist root/namespace")
			}
			for _, a := range node.Attr {
				if a.Name.Space != "" || node.Name.Local != "plist" || a.Name.Local != "version" || a.Value != "1.0" {
					return errors.New("unsupported plist attribute")
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.ProcInst:
			if node.Target != "xml" || roots != 0 {
				return errors.New("unsupported plist processing instruction")
			}
		}
		if depth > 8 || count > 1024 {
			return errors.New("plist structure exceeds budget")
		}
	}
	var root plistNode
	if e := xml.Unmarshal(data, &root); e != nil {
		return e
	}
	if root.XMLName.Local != "plist" || len(root.Children) != 1 || root.Children[0].XMLName.Local != "dict" {
		return errors.New("unsupported plist root")
	}
	nodes := root.Children[0].Children
	if len(nodes)%2 != 0 {
		return errors.New("invalid plist dictionary")
	}
	values := map[string]plistNode{}
	for i := 0; i < len(nodes); i += 2 {
		k, v := nodes[i], nodes[i+1]
		if k.XMLName.Local != "key" || len(k.Children) != 0 || k.Text == "" {
			return errors.New("invalid plist key")
		}
		if _, ok := values[k.Text]; ok {
			return errors.New("duplicate plist key")
		}
		if len(v.Children) != 0 || (v.XMLName.Local != "string" && v.XMLName.Local != "true") {
			return errors.New("unsupported plist value")
		}
		values[k.Text] = v
	}
	parts, e := version(releaseVersion)
	if e != nil {
		return e
	}
	numeric := strings.Join(parts[1:4], ".")
	for k, want := range map[string]string{"CFBundleIdentifier": identifier, "CFBundleExecutable": executable, "CFBundlePackageType": "APPL", "CFBundleVersion": numeric, "CFBundleShortVersionString": numeric, "AccessWeaverReleaseVersion": releaseVersion} {
		v := values[k]
		if v.XMLName.Local != "string" || v.Text != want {
			return errors.New("bundle plist identity differs")
		}
	}
	if values["LSUIElement"].XMLName.Local != "true" {
		return errors.New("bundle UI policy differs")
	}
	return nil
}

type cappedOutput struct{ data []byte }

func (w *cappedOutput) Write(data []byte) (int, error) {
	if len(data) > 65536-len(w.data) {
		return 0, errors.New("native package metadata output exceeds budget")
	}
	w.data = append(w.data, data...)
	return len(data), nil
}
func queryVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/pkgutil", "--pkg-info", BundleID)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
	var out, errOut cappedOutput
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if e := cmd.Run(); e != nil {
		return "", errors.New("native package receipt query failed")
	}
	return receiptVersion(out.data)
}

// Preflight examines only the fixed installed app/receipts and performs no
// filesystem or registry mutation. It does not execute any installed app code.
// The result is a snapshot, not a lock or authorization for subsequent changes.
func Preflight(incoming string) (Result, error) {
	var result Result
	if os.Geteuid() != 0 {
		return result, errors.New("native package preflight requires root")
	}
	if _, e := version(incoming); e != nil {
		return result, e
	}
	parent, e := applications()
	if e != nil {
		return result, fmt.Errorf("inspect Applications container: %w", e)
	}
	defer parent.Close()
	app, e := directoryAt(parent, "AccessWeaver.app")
	if e != nil {
		return result, fmt.Errorf("inspect installed bundle: %w", e)
	}
	defer app.Close()
	info, e := app.Stat()
	if e != nil {
		return result, e
	}
	if info.Mode().Perm() != 0755 {
		return result, errors.New("installed bundle root mode differs")
	}
	encoded, e := readPath(app, ManifestName, 2<<20)
	if e != nil {
		return result, e
	}
	m, e := DecodeManifest(encoded)
	if e != nil {
		return result, e
	}
	important, e := inspectBundle(app, m, encoded)
	if e != nil {
		return result, e
	}
	build, e := decodeBuild(important["Contents/Resources/BUILD-INFO.json"], runtime.GOARCH)
	if e != nil {
		return result, e
	}
	if e = checkPlist(important["Contents/Info.plist"], build.Version); e != nil {
		return result, e
	}
	core := important["Contents/MacOS/accessweaver"]
	cpu := uint32(0x01000007)
	if runtime.GOARCH == "arm64" {
		cpu = 0x0100000c
	}
	if len(core) < 32 || binary.LittleEndian.Uint32(core) != 0xfeedfacf || binary.LittleEndian.Uint32(core[4:]) != cpu || binary.LittleEndian.Uint32(core[12:]) != 2 {
		return result, errors.New("installed core native loader identity differs")
	}
	receipts, e := darwintrust.OpenRootDirectory("/private/var/db/receipts")
	if e != nil {
		return result, e
	}
	defer receipts.Close()
	hashes := map[string]string{}
	states := map[string]syscall.Stat_t{}
	for _, suffix := range []string{".plist", ".bom"} {
		data, st, e := readAt(receipts, BundleID+suffix, 4<<20)
		if e != nil {
			return result, e
		}
		hashes[suffix] = digest(data)
		states[suffix] = st
	}
	installed, e := queryVersion()
	if e != nil {
		return result, e
	}
	if installed != build.Version {
		return result, errors.New("receipt and installed bundle release differ")
	}
	for _, suffix := range []string{".plist", ".bom"} {
		data, st, e := readAt(receipts, BundleID+suffix, 4<<20)
		if e != nil {
			return result, e
		}
		if !sameState(states[suffix], st) || hashes[suffix] != digest(data) {
			return result, errors.New("receipt changed during native metadata query")
		}
	}
	mode, e := decision(incoming, installed)
	if e != nil {
		return result, e
	}
	return Result{IncomingVersion: incoming, InstalledBuild: build, Mode: mode, PayloadSHA256: digest(core), ManifestSHA256: digest(encoded), ReceiptSHA256: hashes, CompleteProtectedInventoryVerified: true}, nil
}
