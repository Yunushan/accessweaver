package packageupgrade

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
)

const desktopBundleID = BundleID + ".desktop"
const desktopExecutable = "accessweaver-launcher"
const desktopRoot = "AccessWeaver Desktop"
const maxDesktopRecord = 64 << 10
const desktopRole = "active-copy-launcher"
const desktopNoticeRoot = "AccessWeaver.app/Contents/Resources"

// A root-owned, content-addressed registration describes only the public
// ordinary-user entry. It cannot select a privileged executable or authority.
// Binary-bound inventory/SBOM stay outside the final application resource seal.
type desktopRecord struct {
	SchemaVersion int            `json:"schemaVersion"`
	Role          string         `json:"role"`
	Build         buildinfo.Info `json:"build"`
	Manifest      Manifest       `json:"manifest"`
	SBOM          string         `json:"compiledSBOM"`
	NoticeRoot    string         `json:"noticeRoot"`
}

func decodeDesktopRecord(data []byte, arch string) (desktopRecord, error) {
	var r desktopRecord
	if len(data) == 0 || len(data) > maxDesktopRecord {
		return r, errors.New("desktop registration exceeds limit")
	}
	if e := strict(data, &r); e != nil {
		return r, e
	}
	if r.SchemaVersion != 1 || r.Role != desktopRole || r.NoticeRoot != desktopNoticeRoot || r.Manifest.SchemaVersion != 1 || r.Manifest.PayloadSBOM != nil {
		return r, errors.New("unsupported desktop registration role/schema")
	}
	encoded, _ := json.Marshal(r.Manifest)
	if _, e := decodeBundleManifest(encoded, desktopBundleID, desktopExecutable, false); e != nil {
		return r, e
	}
	encoded, _ = json.Marshal(r.Build)
	if _, e := decodeBuild(encoded, arch); e != nil {
		return r, e
	}
	if !utf8.ValidString(r.SBOM) || len(r.SBOM) == 0 || len(r.SBOM) > 48<<10 || !json.Valid([]byte(r.SBOM)) {
		return r, errors.New("invalid desktop compiled SBOM extent/encoding")
	}
	if e := uniqueDesktopGraph([]byte(r.SBOM)); e != nil {
		return r, e
	}
	var graph struct {
		Format   string `json:"bomFormat"`
		Spec     string `json:"specVersion"`
		Metadata struct {
			Component struct {
				Type    string `json:"type"`
				Version string `json:"version"`
				Hashes  []struct {
					Algorithm string `json:"alg"`
					Content   string `json:"content"`
				} `json:"hashes"`
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if e := json.Unmarshal([]byte(r.SBOM), &graph); e != nil {
		return r, e
	}
	c := graph.Metadata.Component
	expectedHash := ""
	for _, f := range r.Manifest.Files {
		if f.Path == "Contents/MacOS/"+desktopExecutable {
			expectedHash = f.SHA256
		}
	}
	if graph.Format != "CycloneDX" || graph.Spec != "1.6" || c.Type != "application" || c.Version != r.Build.Version || len(c.Hashes) != 1 || c.Hashes[0].Algorithm != "SHA-256" || c.Hashes[0].Content != expectedHash {
		return r, errors.New("desktop SBOM binary identity differs")
	}
	properties := map[string]string{}
	for _, p := range c.Properties {
		if _, exists := properties[p.Name]; exists {
			return r, errors.New("duplicate desktop SBOM property")
		}
		properties[p.Name] = p.Value
	}
	for key, value := range map[string]string{"source-commit": r.Build.Commit, "source-state": "clean", "target-os": "darwin", "target-arch": arch} {
		if properties["accessweaver:"+key] != value {
			return r, errors.New("desktop SBOM source/target differs")
		}
	}
	return r, nil
}

func desktopRecordName(encoded []byte) string {
	h := sha256.Sum256(encoded)
	return "desktop-" + hex.EncodeToString(h[:]) + ".json"
}

// Both values are stamped into a newly built packaging helper. No environment,
// caller path, installed executable or public plist supplies these seals.
var sealedDesktopRecordSHA256 string
var sealedDesktopComponent string

type DesktopPackageResult struct {
	SchemaVersion                   int    `json:"schemaVersion"`
	Component                       string `json:"component"`
	Phase                           string `json:"phase"`
	Version                         string `json:"version"`
	RecordSHA256                    string `json:"recordSHA256"`
	PublicApplicationVerified       bool   `json:"publicApplicationVerified"`
	MutationPerformed               bool   `json:"mutationPerformed"`
	ProductionQualificationComplete bool   `json:"productionQualificationComplete"`
}

func compiledDesktopIdentity() (buildinfo.Info, string, string, error) {
	b := buildinfo.Current()
	encoded, _ := json.Marshal(b)
	if _, e := decodeBuild(encoded, b.Arch); e != nil {
		return b, "", "", e
	}
	if !hash.MatchString(sealedDesktopRecordSHA256) || (sealedDesktopComponent != "metadata" && sealedDesktopComponent != "application") {
		return b, "", "", errors.New("desktop packaging helper has no compiled component/record seal")
	}
	return b, sealedDesktopComponent, sealedDesktopRecordSHA256, nil
}

// The graph is a detached string inside the strict registration envelope, so
// reject duplicate object keys/ambiguous nesting before interpreting identity.
func uniqueDesktopGraph(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	count := 0
	var visit func(int) error
	visit = func(depth int) error {
		count++
		if depth > 32 || count > 8192 {
			return errors.New("desktop graph structure exceeds budget")
		}
		token, e := d.Token()
		if e != nil {
			return e
		}
		if token == nil {
			return errors.New("null desktop graph field")
		}
		opening, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch opening {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate desktop graph object key")
				}
				seen[name] = true
				if e = visit(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = visit(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid desktop graph delimiter")
		}
		closing, e := d.Token()
		if e != nil {
			return e
		}
		if opening == '{' && closing != json.Delim('}') || opening == '[' && closing != json.Delim(']') {
			return errors.New("desktop graph closing delimiter differs")
		}
		return nil
	}
	if e := visit(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing desktop graph value")
	}
	return nil
}
