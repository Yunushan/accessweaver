package packageupgrade

import (
	"encoding/json"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"strings"
	"testing"
)

func TestReleaseOrderAndCanonicalBounds(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1"}
	for i, a := range ordered {
		for j, b := range ordered {
			n, e := CompareVersions(a, b)
			if e != nil || i < j && n >= 0 || i == j && n != 0 || i > j && n <= 0 {
				t.Fatalf("%q vs %q = %d, %v", a, b, n, e)
			}
		}
	}
	for _, v := range []string{"v1.2.3", "01.2.3", "1.2.3-alpha.01", "10000.0.0", "1.100.0", "1.0.100", "1.2", "1.2.3+", "1.2.3-" + strings.Repeat("x", 251), "1.2.3\n"} {
		if _, e := CompareVersions(v, "1.2.3"); e == nil {
			t.Errorf("accepted noncanonical release %q", v)
		}
	}
	for _, pair := range [][2]string{{"1.2.3+build.1", "1.2.3+build.2"}, {"0.1.0-alpha", "0.1.0-alpha"}} {
		if n, e := CompareVersions(pair[0], pair[1]); e != nil || n != 0 {
			t.Fatal(n, e)
		}
	}
	a := "1.0.0-" + strings.Repeat("9", 200)
	b := "1.0.0-1" + strings.Repeat("0", 200)
	if n, e := CompareVersions(a, b); e != nil || n >= 0 {
		t.Fatal("large identifiers overflowed", n, e)
	}
	if _, e := decision("0.1.0-alpha", "0.1.0"); e == nil {
		t.Fatal("stable to prerelease downgrade accepted")
	}
}
func fixture() Manifest {
	m := Manifest{SchemaVersion: 1, BundleIdentifier: BundleID, Directories: []Directory{{"Contents", "0755"}, {"Contents/MacOS", "0755"}, {"Contents/Resources", "0755"}}}
	for _, p := range []string{"Contents/Info.plist", "Contents/MacOS/accessweaver", "Contents/Resources/BUILD-INFO.json", "Contents/Resources/SBOM.cdx.json"} {
		mode := "0644"
		if strings.Contains(p, "MacOS/") {
			mode = "0755"
		}
		m.Files = append(m.Files, File{p, 32, strings.Repeat("a", 64), mode})
	}
	return m
}
func TestManifestRejectsAmbiguousAndUnsafeInventories(t *testing.T) {
	good, _ := json.Marshal(fixture())
	if _, e := DecodeManifest(good); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*Manifest){
		"traversal": func(m *Manifest) { m.Files[0].Path = "../outside" }, "root": func(m *Manifest) { m.Directories[0].Path = "." }, "duplicate": func(m *Manifest) { m.Files = append(m.Files, m.Files[0]) }, "directory collision": func(m *Manifest) { m.Directories = append(m.Directories, Directory{m.Files[0].Path, "0755"}) }, "parent missing": func(m *Manifest) { m.Directories = m.Directories[1:] }, "unknown identity": func(m *Manifest) { m.BundleIdentifier = "other" }, "self inventory": func(m *Manifest) { m.Files[0].Path = ManifestName }, "write permission": func(m *Manifest) { m.Files[0].Mode = "0666" }, "large file": func(m *Manifest) { m.Files[0].Bytes = 64<<20 + 1 }, "aggregate": func(m *Manifest) {
			for i := range m.Files {
				m.Files[i].Bytes = 64 << 20
			}
		}, "invalid hash": func(m *Manifest) { m.Files[0].SHA256 = "invalid" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			change(&m)
			raw, _ := json.Marshal(m)
			if _, e := DecodeManifest(raw); e == nil {
				t.Fatal("accepted unsafe inventory")
			}
		})
	}
	for _, raw := range [][]byte{append(good, []byte(" {}")...),
		[]byte(strings.Replace(string(good), `"bytes":32`, `"bytes":null`, 1)), []byte(strings.Replace(string(good), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)), []byte(strings.Replace(string(good), `"schemaVersion"`, `"SchemaVersion"`, 1)), []byte(strings.Replace(string(good), `"path":"Contents/Info.plist"`, `"path":"Contents/Info.plist","path":"Contents/Info.plist"`, 1))} {
		if _, e := DecodeManifest(raw); e == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}
func TestBuildAndNativeReceiptIdentity(t *testing.T) {
	b := buildinfo.Info{Version: "0.1.0-alpha", Commit: strings.Repeat("a", 40), SourceState: "clean", BuiltAt: "2026-11-03T00:00:00Z", GoVersion: "go1.27.3", Platform: "darwin", Arch: "arm64"}
	raw, _ := json.Marshal(b)
	if _, e := decodeBuild(raw, "arm64"); e != nil {
		t.Fatal(e)
	}
	if _, e := decodeBuild(raw, "amd64"); e == nil {
		t.Fatal("foreign target accepted")
	}
	b.BuiltAt = "invalid"
	raw, _ = json.Marshal(b)
	if _, e := decodeBuild(raw, "arm64"); e == nil {
		t.Fatal("unknown timestamp accepted")
	}
	receipt := "package-id: " + BundleID + "\nversion: 0.1.0-alpha\nvolume: /\nlocation: \ninstall-time: 12345\n"
	if v, e := receiptVersion([]byte(receipt)); e != nil || v != "0.1.0-alpha" {
		t.Fatal(v, e)
	}
	for _, bad := range []string{receipt + "location: /\n", strings.Replace(receipt, BundleID, "other", 1), strings.Replace(receipt, "volume: /", "volume: /other", 1), strings.Replace(receipt, "0.1.0-alpha", "v0.1.0", 1), receipt + "unknown: x\n"} {
		if _, e := receiptVersion([]byte(bad)); e == nil {
			t.Fatal("bad receipt metadata accepted")
		}
	}
}
