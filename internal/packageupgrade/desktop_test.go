package packageupgrade

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
)

func desktopFixture() desktopRecord {
	m := fixture()
	m.BundleIdentifier = desktopBundleID
	m.Files = m.Files[:3]
	m.Files[1].Path = "Contents/MacOS/" + desktopExecutable
	b := buildinfo.Info{Version: "0.1.0-alpha", Commit: strings.Repeat("a", 40), SourceState: "clean", BuiltAt: "2026-11-03T00:00:00Z", GoVersion: "go1.27.3", Platform: "darwin", Arch: "amd64"}
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","version":"0.1.0-alpha","hashes":[{"alg":"SHA-256","content":"` + strings.Repeat("a", 64) + `"}],"properties":[{"name":"accessweaver:source-commit","value":"` + b.Commit + `"},{"name":"accessweaver:source-state","value":"clean"},{"name":"accessweaver:target-os","value":"darwin"},{"name":"accessweaver:target-arch","value":"amd64"}]}}}`
	return desktopRecord{SchemaVersion: 1, Role: desktopRole, Build: b, Manifest: m, SBOM: bom, NoticeRoot: desktopNoticeRoot}
}
func TestDesktopRegistrationCannotAuthorizeCoreOrUnboundPublicEntry(t *testing.T) {
	r := desktopFixture()
	encoded, _ := json.Marshal(r)
	if _, e := decodeDesktopRecord(encoded, "amd64"); e != nil {
		t.Fatal(e)
	}
	m, _ := json.Marshal(r.Manifest)
	if _, e := DecodeManifest(m); e == nil {
		t.Fatal("public inventory authorized installed core")
	}
	for _, bad := range []string{string(encoded) + string(encoded), strings.Replace(string(encoded), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1), strings.Replace(string(encoded), `"role":"active-copy-launcher"`, `"Role":"active-copy-launcher"`, 1), strings.Replace(string(encoded), `"compiledSBOM":`, `"unexpected":0,"compiledSBOM":`, 1)} {
		if _, e := decodeDesktopRecord([]byte(bad), "amd64"); e == nil {
			t.Fatal("ambiguous registration accepted")
		}
	}
	cases := map[string]func(*desktopRecord){
		"notice root": func(r *desktopRecord) { r.NoticeRoot = "../other" }, "duplicate graph": func(r *desktopRecord) {
			r.SBOM = strings.Replace(r.SBOM, `"bomFormat":"CycloneDX"`, `"bomFormat":"other","bomFormat":"CycloneDX"`, 1)
		}, "wrong role": func(r *desktopRecord) { r.Role = "core" }, "wrong bundle": func(r *desktopRecord) { r.Manifest.BundleIdentifier = BundleID }, "other executable": func(r *desktopRecord) { r.Manifest.Files[1].Path = "Contents/MacOS/other" }, "wrong mode": func(r *desktopRecord) { r.Manifest.Files[1].Mode = "0644" }, "dirty": func(r *desktopRecord) { r.Build.SourceState = "dirty" }, "wrong architecture": func(r *desktopRecord) { r.Build.Arch = "arm64" }, "unbound binary": func(r *desktopRecord) { r.Manifest.Files[1].SHA256 = strings.Repeat("b", 64) }, "unbound source": func(r *desktopRecord) { r.Build.Commit = strings.Repeat("b", 40) }, "oversized graph": func(r *desktopRecord) { r.SBOM = strings.Repeat(" ", maxDesktopRecord) }, "embedded SBOM": func(r *desktopRecord) {
			r.Manifest.Files = append(r.Manifest.Files, File{embeddedPayloadSBOM, 32, strings.Repeat("a", 64), "0644"})
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := desktopFixture()
			change(&r)
			raw, _ := json.Marshal(r)
			if _, e := decodeDesktopRecord(raw, "amd64"); e == nil {
				t.Fatal("unsafe registration accepted")
			}
		})
	}
}

// Graph/hash data come from a previously independently authenticated native
// launcher. No executable bytes are retained or executed by this portable test.
// This checks older registration readability, not native installation.
func TestDesktopRegistrationAcceptsRealCompiledGraph(t *testing.T) {
	data, e := os.ReadFile("testdata/desktop-registration-real-graph.json")
	if e != nil {
		t.Fatal(e)
	}
	r, e := decodeDesktopRecord(data, "amd64")
	if e != nil {
		t.Fatal(e)
	}
	if r.Build.Commit != "ac640bf803da036e769e25a7a6b9bab2a66ea4fa" {
		t.Fatal("fixture source changed")
	}
}
