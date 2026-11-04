package packageupgrade

import (
	"strings"
	"testing"
)

func TestRemovalReceiptMetadataRequiresExactProductRootAndVersion(t *testing.T) {
	expected := removalReceiptExpectation{ID: removalCoreReceiptID, Version: "0.1.1-alpha", Location: "/Library/Application Support/AccessWeaver Incoming/" + strings.Repeat("a", 64)}
	raw := "package-id: " + expected.ID + "\nversion: " + expected.Version + "\nvolume: /\nlocation: " + strings.TrimPrefix(expected.Location, "/") + "\ninstall-time: 12345\n"
	if e := checkRemovalReceiptMetadata([]byte(raw), expected); e != nil {
		t.Fatal(e)
	}
	absolute := strings.Replace(raw, "location: Library", "location: /Library", 1)
	if e := checkRemovalReceiptMetadata([]byte(absolute), expected); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"identifier", "version", "volume", "location", "time", "duplicate", "unknown", "invalid-utf8", "oversize", "unsafe-expectation"} {
		t.Run(kind, func(t *testing.T) {
			data := []byte(raw)
			want := expected
			switch kind {
			case "identifier":
				data = []byte(strings.Replace(raw, expected.ID, desktopBundleID, 1))
			case "version":
				data = []byte(strings.Replace(raw, expected.Version, "0.1.0-alpha", 1))
			case "volume":
				data = []byte(strings.Replace(raw, "volume: /", "volume: /Volumes/Other", 1))
			case "location":
				data = []byte(strings.Replace(raw, "location: Library", "location: ../Library", 1))
			case "time":
				data = []byte(strings.Replace(raw, "install-time: 12345", "install-time: -1", 1))
			case "duplicate":
				data = append(data, []byte("location: \n")...)
			case "unknown":
				data = append(data, []byte("caller-root: /tmp\n")...)
			case "invalid-utf8":
				data = []byte{255}
			case "oversize":
				data = []byte(strings.Repeat("x", 65537))
			case "unsafe-expectation":
				want.ID = "--forget"
			}
			if e := checkRemovalReceiptMetadata(data, want); e == nil {
				t.Fatal("unowned receipt accepted")
			}
		})
	}
}
func TestRemovalReceiptFileListMatchesOnlyExpectedCanonicalPaths(t *testing.T) {
	expected := []string{"App", "App/Contents", "App/Contents/core"}
	for _, data := range []string{"App\nApp/Contents\nApp/Contents/core\n", ".\n./App\n./App/Contents\n./App/Contents/core\n"} {
		paths, e := checkRemovalReceiptPaths([]byte(data), expected)
		if e != nil || strings.Join(paths, "|") != strings.Join(expected, "|") {
			t.Fatal(paths, e)
		}
	}
	for _, data := range []string{"", "App\nApp/Contents\n", "App\nApp/Contents\nApp/Contents/core\nother\n", "App\n./App\nApp/Contents\nApp/Contents/core\n", "App\n../escape\n", "/App\nApp/Contents\nApp/Contents/core\n", ".\n./\nApp\nApp/Contents\nApp/Contents/core\n", "App\n\nApp/Contents\nApp/Contents/core\n", strings.Repeat("x", maxRemovalReceiptPathsBytes+1)} {
		if _, e := checkRemovalReceiptPaths([]byte(data), expected); e == nil {
			t.Fatal("unsafe or incomplete BOM file list accepted")
		}
	}
	for _, bad := range [][]string{{"App", "App"}, {"../outside"}, {"App", "/etc/passwd"}} {
		if _, e := checkRemovalReceiptPaths([]byte("App\n"), bad); e == nil {
			t.Fatal("invalid expected path admitted")
		}
	}
}
func TestRemovalReceiptIDsAreFixedOrContentAddressed(t *testing.T) {
	for _, id := range []string{removalCoreReceiptID, desktopBundleID, desktopBundleID + ".registration." + strings.Repeat("a", 64)} {
		if !validRemovalReceiptID(id) {
			t.Fatal("fixed identifier refused", id)
		}
	}
	for _, id := range []string{"", BundleID, desktopBundleID + ".registration.", desktopBundleID + ".registration." + strings.Repeat("A", 64), desktopBundleID + ".other", "--files", "../../other"} {
		if validRemovalReceiptID(id) {
			t.Fatal("uncontrolled identifier admitted", id)
		}
	}
}
func TestRemovalReceiptLayoutsIncludeOnlyTheirSealedSidecars(t *testing.T) {
	m := Manifest{SchemaVersion: 2, Directories: []Directory{{Path: "Contents", Mode: "0755"}}, Files: []File{{Path: "Contents/core"}}}
	source := strings.Join(removalBundleReceiptPaths(m, false, true), "|")
	if !strings.Contains(source, "|INSTALL-MANIFEST.json|payload-SBOM.cdx.json") {
		t.Fatal("schema2 sidecars missing", source)
	}
	legacy := strings.Join(removalBundleReceiptPaths(m, true, false), "|")
	if strings.Contains(legacy, "INSTALL-MANIFEST") || strings.Contains(legacy, "payload-SBOM") {
		t.Fatal("public app receipt acquired core sidecars", legacy)
	}
	m.SchemaVersion = 1
	embedded := strings.Join(removalBundleReceiptPaths(m, true, true), "|")
	if !strings.Contains(embedded, "AccessWeaver.app/"+ManifestName) || strings.Contains(embedded, "payload-SBOM.cdx.json") {
		t.Fatal("legacy receipt inventory differs", embedded)
	}
}
