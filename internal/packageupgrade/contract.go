// Package packageupgrade validates installed macOS packages without executing them.
// Preflight is read-only evidence, not an authorization token for later mutation.
package packageupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
)

const BundleID = "io.github.yunushan.accessweaver"
const MaxFiles = 4096
const MaxBytes = 128 << 20
const ManifestName = "Contents/Resources/INSTALL-MANIFEST.json"

var release = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var relative = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$`)
var hash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var source = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)

func numeric(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func version(value string) ([]string, error) {
	if len(value) > 256 {
		return nil, errors.New("release version exceeds limit")
	}
	parts := release.FindStringSubmatch(value)
	if parts == nil {
		return nil, errors.New("expected canonical release version")
	}
	for i, limit := range []uint64{9999, 99, 99} {
		v, e := strconv.ParseUint(parts[i+1], 10, 16)
		if e != nil || v > limit {
			return nil, errors.New("release exceeds bundle version fields")
		}
	}
	for _, id := range strings.Split(parts[4], ".") {
		if numeric(id) && len(id) > 1 && id[0] == '0' {
			return nil, errors.New("numeric prerelease has leading zero")
		}
	}
	return parts, nil
}
func numericOrder(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

// CompareVersions compares full canonical SemVer without integer overflow.
// Build metadata does not change precedence; Apple's numeric bundle limits apply.
func CompareVersions(a, b string) (int, error) {
	x, e := version(a)
	if e != nil {
		return 0, e
	}
	y, e := version(b)
	if e != nil {
		return 0, e
	}
	for i := 1; i <= 3; i++ {
		if n := numericOrder(x[i], y[i]); n != 0 {
			return n, nil
		}
	}
	if x[4] == y[4] {
		return 0, nil
	}
	if x[4] == "" {
		return 1, nil
	}
	if y[4] == "" {
		return -1, nil
	}
	u, v := strings.Split(x[4], "."), strings.Split(y[4], ".")
	for i := 0; i < len(u) && i < len(v); i++ {
		n := 0
		switch {
		case numeric(u[i]) && numeric(v[i]):
			n = numericOrder(u[i], v[i])
		case numeric(u[i]):
			n = -1
		case numeric(v[i]):
			n = 1
		default:
			n = strings.Compare(u[i], v[i])
		}
		if n != 0 {
			return n, nil
		}
	}
	if len(u) < len(v) {
		return -1, nil
	}
	if len(u) > len(v) {
		return 1, nil
	}
	return 0, nil
}

type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
}
type Directory struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}
type Manifest struct {
	SchemaVersion    int         `json:"schemaVersion"`
	BundleIdentifier string      `json:"bundleIdentifier"`
	Files            []File      `json:"files"`
	Directories      []Directory `json:"directories"`
}

func strict(data []byte, into any) error {
	if len(data) > 2<<20 || !utf8.Valid(data) {
		return errors.New("JSON exceeds encoding/size budget")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	count := 0
	var visit func(int, reflect.Type) error
	visit = func(depth int, shape reflect.Type) error {
		count++
		if depth > 32 || count > 65536 {
			return errors.New("JSON structure exceeds limit")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		opening, ok := t.(json.Delim)
		if !ok {
			if t == nil {
				return errors.New("null JSON field is unsupported")
			}
			return nil
		}
		switch opening {
		case '{':
			if shape.Kind() != reflect.Struct {
				return errors.New("JSON object shape differs")
			}
			fields := map[string]reflect.Type{}
			for i := 0; i < shape.NumField(); i++ {
				field := shape.Field(i)
				fields[strings.Split(field.Tag.Get("json"), ",")[0]] = field.Type
			}
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := k.(string)
				if !ok || keys[name] {
					return errors.New("duplicate JSON key")
				}
				keys[name] = true
				field, known := fields[name]
				if !known {
					return errors.New("unknown or noncanonical JSON field")
				}
				if e = visit(depth+1, field); e != nil {
					return e
				}
			}
		case '[':
			if shape.Kind() != reflect.Slice {
				return errors.New("JSON array shape differs")
			}
			for d.More() {
				if e = visit(depth+1, shape.Elem()); e != nil {
					return e
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		closing, e := d.Token()
		if e != nil {
			return e
		}
		if opening == '{' && closing != json.Delim('}') || opening == '[' && closing != json.Delim(']') {
			return errors.New("invalid JSON closing delimiter")
		}
		return nil
	}
	if e := visit(0, reflect.TypeOf(into).Elem()); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON value")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(into)
}
func validPath(value string) bool {
	return value != "." && value != ".." && len(value) <= 4096 && relative.MatchString(value) && path.Clean(value) == value && len(strings.Split(value, "/")) <= 32 && !strings.Contains("/"+value+"/", "/../")
}
func DecodeManifest(data []byte) (Manifest, error) {
	var m Manifest
	if e := strict(data, &m); e != nil {
		return m, e
	}
	if m.SchemaVersion != 1 || m.BundleIdentifier != BundleID || len(m.Files) < 4 || len(m.Files)+len(m.Directories) > MaxFiles {
		return m, errors.New("unsupported manifest identity/inventory")
	}
	names := map[string]bool{}
	dirs := map[string]bool{}
	total := int64(0)
	for _, d := range m.Directories {
		if !validPath(d.Path) || names[d.Path] || d.Mode != "0755" {
			return m, errors.New("unsafe manifest directory")
		}
		names[d.Path] = true
		dirs[d.Path] = true
	}
	required := map[string]bool{"Contents/Info.plist": false, "Contents/MacOS/accessweaver": false, "Contents/Resources/BUILD-INFO.json": false, "Contents/Resources/SBOM.cdx.json": false}
	for _, f := range m.Files {
		if !validPath(f.Path) || names[f.Path] || f.Path == ManifestName || f.Bytes < 0 || f.Bytes > 64<<20 || !hash.MatchString(f.SHA256) || f.Mode != "0644" && !(f.Path == "Contents/MacOS/accessweaver" && f.Mode == "0755") {
			return m, errors.New("unsafe manifest file")
		}
		if f.Path == "Contents/MacOS/accessweaver" && f.Mode != "0755" {
			return m, errors.New("core is not executable")
		}
		total += f.Bytes
		if total > MaxBytes {
			return m, errors.New("manifest exceeds total bytes")
		}
		names[f.Path] = true
		if _, ok := required[f.Path]; ok {
			required[f.Path] = true
		}
	}
	for _, found := range required {
		if !found {
			return m, errors.New("required bundle file is missing")
		}
	}
	for name := range names {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if !dirs[parent] {
				return m, errors.New("manifest parent directory is missing")
			}
		}
	}
	return m, nil
}
func decodeBuild(data []byte, arch string) (buildinfo.Info, error) {
	var b buildinfo.Info
	if len(data) > 16384 {
		return b, errors.New("build identity exceeds limit")
	}
	if e := strict(data, &b); e != nil {
		return b, e
	}
	if _, e := version(b.Version); e != nil {
		return b, e
	}
	if !source.MatchString(b.Commit) || b.SourceState != "clean" || b.Platform != "darwin" || b.Arch != arch || !strings.HasPrefix(b.GoVersion, "go1.") {
		return b, errors.New("unsupported installed build identity")
	}
	stamp, e := time.Parse(time.RFC3339, b.BuiltAt)
	if e != nil || stamp.UTC().Format(time.RFC3339) != b.BuiltAt {
		return b, errors.New("invalid canonical build timestamp")
	}
	return b, nil
}
func receiptVersion(data []byte) (string, error) {
	if len(data) > 65536 || !utf8.Valid(data) {
		return "", errors.New("receipt metadata exceeds limit")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || values[k] != "" {
			return "", errors.New("invalid receipt metadata fields")
		}
		switch k {
		case "package-id", "version", "volume", "location", "install-time":
		default:
			return "", errors.New("unsupported receipt metadata field")
		}
		if _, exists := values[k]; exists {
			return "", errors.New("duplicate receipt field")
		}
		values[k] = strings.TrimSpace(v)
	}
	if len(values) != 5 || values["package-id"] != BundleID || values["volume"] != "/" || values["location"] != "" && values["location"] != "/" || !numeric(values["install-time"]) {
		return "", errors.New("receipt does not describe fixed system package")
	}
	if _, e := version(values["version"]); e != nil {
		return "", e
	}
	return values["version"], nil
}

type Result struct {
	IncomingVersion                    string            `json:"incomingVersion"`
	InstalledBuild                     buildinfo.Info    `json:"installedBuild"`
	Mode                               string            `json:"mode"`
	PayloadSHA256                      string            `json:"payloadSHA256"`
	ManifestSHA256                     string            `json:"manifestSHA256"`
	ReceiptSHA256                      map[string]string `json:"receiptSHA256"`
	CompleteProtectedInventoryVerified bool              `json:"completeProtectedInventoryVerified"`
	MutationPerformed                  bool              `json:"mutationPerformed"`
	UpgradeExecuted                    bool              `json:"upgradeExecuted"`
	ProductionQualificationComplete    bool              `json:"productionQualificationComplete"`
}

func decision(incoming, installed string) (string, error) {
	n, e := CompareVersions(incoming, installed)
	if e != nil {
		return "", e
	}
	if n < 0 {
		return "", fmt.Errorf("installed version %s is newer than incoming release", installed)
	}
	if n == 0 {
		return "reinstall", nil
	}
	return "upgrade", nil
}
