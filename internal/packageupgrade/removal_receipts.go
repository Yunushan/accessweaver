package packageupgrade

import (
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

const removalScope = "core-history-public-app-registrations-incoming-receipts"
const removalCoreReceiptID = BundleID + ".deployment"
const maxRemovalReceiptPathsBytes = 2 << 20

type removalReceiptExpectation struct {
	ID       string
	Version  string
	Location string
	Paths    []string
}

func validRemovalReceiptID(id string) bool {
	if id == removalCoreReceiptID || id == desktopBundleID {
		return true
	}
	prefix := desktopBundleID + ".registration."
	return strings.HasPrefix(id, prefix) && hash.MatchString(strings.TrimPrefix(id, prefix))
}
func receiptActionPair(plan removalPlan, bom removalFileAction) (string, removalFileAction, error) {
	if bom.root < 0 || bom.root >= len(plan.Roots) {
		return "", removalFileAction{}, errors.New("invalid receipt action root")
	}
	root := plan.Roots[bom.root]
	if root.Kind != "receipts" || bom.object <= 0 || bom.object >= len(root.Objects) {
		return "", removalFileAction{}, errors.New("invalid receipt action")
	}
	id, suffix := strings.CutSuffix(root.Objects[bom.object].Path, ".bom")
	if !suffix || !validRemovalReceiptID(id) {
		return "", removalFileAction{}, errors.New("invalid receipt action identity")
	}
	for j, object := range root.Objects {
		if object.Path == id+".plist" {
			return id, removalFileAction{bom.root, j}, nil
		}
	}
	return "", removalFileAction{}, errors.New("receipt action plist is missing")
}

func checkRemovalReceiptMetadata(data []byte, expected removalReceiptExpectation) error {
	if !validRemovalReceiptID(expected.ID) || expected.Location == "" || !strings.HasPrefix(expected.Location, "/") {
		return errors.New("invalid fixed removal receipt expectation")
	}
	if _, e := version(expected.Version); e != nil {
		return e
	}
	if len(data) == 0 || len(data) > 65536 || !utf8.Valid(data) {
		return errors.New("removal receipt metadata exceeds encoding or size limit")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return errors.New("invalid removal receipt metadata")
		}
		if _, exists := values[key]; exists {
			return errors.New("duplicate removal receipt metadata")
		}
		switch key {
		case "package-id", "version", "volume", "location", "install-time":
		default:
			return errors.New("unexpected removal receipt metadata")
		}
		values[key] = strings.TrimSpace(value)
	}
	location := values["location"]
	if len(values) != 5 || values["package-id"] != expected.ID || values["version"] != expected.Version || values["volume"] != "/" || (location != expected.Location && "/"+location != expected.Location) || !numeric(values["install-time"]) {
		return errors.New("removal receipt does not match the protected product inventory")
	}
	return nil
}
func checkRemovalReceiptPaths(data []byte, expected []string) ([]string, error) {
	if len(data) == 0 || len(data) > maxRemovalReceiptPathsBytes || !utf8.Valid(data) || len(expected) == 0 || len(expected) > MaxFiles+5 {
		return nil, errors.New("removal receipt file-list extent differs")
	}
	wanted := map[string]bool{}
	for _, name := range expected {
		if !validPath(name) || wanted[name] {
			return nil, errors.New("invalid expected removal receipt path")
		}
		wanted[name] = true
	}
	text := strings.TrimSuffix(string(data), "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > MaxFiles+6 {
		return nil, errors.New("removal receipt file-list capacity exceeded")
	}
	seen := map[string]bool{}
	rootSeen := false
	for _, line := range lines {
		name := strings.TrimSuffix(line, "\r")
		if name == "." || name == "./" {
			if rootSeen {
				return nil, errors.New("duplicate receipt root")
			}
			rootSeen = true
			continue
		}
		name = strings.TrimPrefix(name, "./")
		if !validPath(name) || seen[name] || !wanted[name] {
			return nil, errors.New("unknown, duplicate or unsafe removal receipt path")
		}
		seen[name] = true
	}
	if len(seen) != len(wanted) {
		return nil, errors.New("removal receipt omits protected inventory paths")
	}
	paths := make([]string, 0, len(seen))
	for name := range seen {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return paths, nil
}
func removalBundleReceiptPaths(m Manifest, embedded, container bool) []string {
	paths := []string{"AccessWeaver.app"}
	for _, d := range m.Directories {
		paths = append(paths, "AccessWeaver.app/"+d.Path)
	}
	for _, f := range m.Files {
		paths = append(paths, "AccessWeaver.app/"+f.Path)
	}
	if container {
		if embedded {
			paths = append(paths, "AccessWeaver.app/"+ManifestName)
		} else {
			paths = append(paths, detachedDeploymentManifest)
		}
		if m.SchemaVersion == 2 {
			paths = append(paths, PayloadSBOMName)
		}
	}
	sort.Strings(paths)
	return paths
}
