package packageupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"strings"
)

const maxRemovalPlanBytes = 2 << 20
const maxRemovalPlanObjects = 16384

// A plan is private data, not a deletion capability. Roots are fixed roles;
// caller paths, profiles, policy, backups and authority history are excluded.
// Actual mutation/retry must revalidate these identities under both leases.
type removalPlan struct {
	SchemaVersion       int               `json:"schemaVersion"`
	Generation          uint64            `json:"generation"`
	Active              deploymentSlot    `json:"active"`
	DesktopRecordSHA256 string            `json:"desktopRecordSHA256"`
	Roots               []removalPlanRoot `json:"roots"`
}
type removalPlanRoot struct {
	Kind         string              `json:"kind"`
	Key          string              `json:"key"`
	Identity     deploymentIdentity  `json:"identity"`
	ParentDevice uint64              `json:"parentDevice"`
	ParentInode  uint64              `json:"parentInode"`
	Objects      []removalPlanObject `json:"objects"`
}
type removalPlanObject struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Mode    string `json:"mode"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Bytes   int64  `json:"bytes"`
	MtimeNs int64  `json:"mtimeNs"`
	CtimeNs int64  `json:"ctimeNs"`
	SHA256  string `json:"sha256"`
}

func (p removalPlan) validate() error {
	if p.SchemaVersion != 1 || p.Generation == 0 || !hash.MatchString(p.DesktopRecordSHA256) || len(p.Roots) < 5 || len(p.Roots) > 2*maxRetainedDeployments+3 {
		return errors.New("invalid removal plan identity or extent")
	}
	if e := p.Active.validate(); e != nil {
		return e
	}
	cores := map[string]deploymentIdentity{}
	incoming := map[string]deploymentIdentity{}
	vnodes := map[[2]uint64]bool{}
	registry := map[string]bool{}
	receipts := map[string]bool{}
	counts := map[string]int{}
	previous := ""
	total := 0
	active := false
	for _, root := range p.Roots {
		key := root.Kind + "\x00" + root.Key
		if key <= previous || root.ParentInode == 0 || len(root.Objects) == 0 || len(root.Objects) > MaxFiles+4 {
			return errors.New("invalid removal root ordering or extent")
		}
		previous = key
		counts[root.Kind]++
		switch root.Kind {
		case "core":
			if !slotName.MatchString(root.Key) {
				return errors.New("invalid removal core key")
			}
			if e := root.Identity.validate(); e != nil {
				return e
			}
			order, e := CompareVersions(root.Identity.Version, p.Active.Identity.Version)
			if e != nil || order > 0 {
				return errors.New("removal core is newer than active release")
			}
			if old, ok := cores[root.Identity.ManifestSHA256]; ok && old != root.Identity {
				return errors.New("conflicting removal core identity")
			}
			cores[root.Identity.ManifestSHA256] = root.Identity
			if root.Key == p.Active.ID {
				first := root.Objects[0]
				if root.Identity != p.Active.Identity || first.Device != uint64(p.Active.Device) || first.Inode != p.Active.Inode {
					return errors.New("removal active vnode differs")
				}
				active = true
			}
		case "incoming":
			if !hash.MatchString(root.Key) || root.Key != root.Identity.ManifestSHA256 {
				return errors.New("invalid removal incoming key")
			}
			if e := root.Identity.validate(); e != nil {
				return e
			}
			incoming[root.Key] = root.Identity
		case "public":
			if root.Key != "AccessWeaver.app" || root.Identity != (deploymentIdentity{}) {
				return errors.New("invalid removal public root")
			}
		case "registrations":
			if root.Key != desktopRoot || root.Identity != (deploymentIdentity{}) {
				return errors.New("invalid removal registration root")
			}
		case "receipts":
			if root.Key != "receipts" || root.Identity != (deploymentIdentity{}) {
				return errors.New("invalid removal receipts root")
			}
		default:
			return errors.New("unknown removal root role")
		}
		parents := map[string]bool{}
		folded := map[string]bool{}
		last := ""
		var device uint64
		for i, o := range root.Objects {
			total++
			if total > maxRemovalPlanObjects || o.Inode == 0 || i > 0 && (!validRemovalObjectPath(root.Kind, o.Path) || i > 1 && o.Path <= last) {
				return errors.New("invalid removal object extent, path or ordering")
			}
			if i == 0 {
				if o.Path != "." || o.Kind != "directory" {
					return errors.New("removal root object is absent")
				}
				device = o.Device
			} else if !parents[path.Dir(o.Path)] {
				return errors.New("removal object parent is absent")
			}
			fold := strings.ToLower(o.Path)
			if folded[fold] || o.Device != device {
				return errors.New("aliased or cross-device removal object")
			}
			vnode := [2]uint64{o.Device, o.Inode}
			if vnodes[vnode] {
				return errors.New("duplicate removal vnode")
			}
			vnodes[vnode] = true
			folded[fold] = true
			last = o.Path
			switch o.Kind {
			case "directory":
				if o.Mode != "0755" || o.Bytes != 0 || o.SHA256 != "" || o.MtimeNs != 0 || o.CtimeNs != 0 {
					return errors.New("invalid removal directory")
				}
				if i > 0 && (root.Kind == "registrations" || root.Kind == "receipts") {
					return errors.New("unexpected nested removal metadata")
				}
				parents[o.Path] = true
			case "file":
				if i == 0 || o.Bytes < 0 || o.Bytes > 64<<20 || !hash.MatchString(o.SHA256) || o.Mode != "0644" && o.Mode != "0755" {
					return errors.New("invalid removal file")
				}
				if root.Kind == "registrations" {
					if o.Mode != "0644" || o.Bytes <= 0 || o.Bytes > maxDesktopRecord || o.Path != "desktop-"+o.SHA256+".json" {
						return errors.New("unbound removal registration")
					}
					registry[o.SHA256] = true
				}
				if root.Kind == "receipts" {
					ext := path.Ext(o.Path)
					id := strings.TrimSuffix(o.Path, ext)
					if (ext != ".plist" && ext != ".bom") || !validRemovalReceiptID(id) || o.Mode != "0644" || o.Bytes <= 0 || o.Bytes > 4<<20 {
						return errors.New("invalid removal receipt file")
					}
					receipts[o.Path] = true
				}
			default:
				return errors.New("invalid removal object type")
			}
		}
		if len(root.Objects) < 2 {
			return errors.New("empty removal payload root")
		}
	}
	if !active || counts["core"] < 1 || counts["core"] > maxRetainedDeployments || counts["incoming"] != len(cores) || counts["public"] != 1 || counts["registrations"] != 1 || counts["receipts"] != 1 || !registry[p.DesktopRecordSHA256] {
		return errors.New("removal plan roles or selected registration differ")
	}
	for key, id := range cores {
		if incoming[key] != id {
			return errors.New("removal incoming/core identities differ")
		}
	}
	expected := map[string]bool{}
	for _, id := range []string{removalCoreReceiptID, desktopBundleID} {
		expected[id+".plist"] = true
		expected[id+".bom"] = true
	}
	for seal := range registry {
		id := desktopBundleID + ".registration." + seal
		expected[id+".plist"] = true
		expected[id+".bom"] = true
	}
	if len(registry) > maxRetainedDeployments {
		return errors.New("removal registration capacity exceeded")
	}
	if len(receipts) != len(expected) {
		return errors.New("removal receipt set differs")
	}
	for name := range expected {
		if !receipts[name] {
			return errors.New("removal receipt identity is absent")
		}
	}
	return nil
}
func encodeRemovalPlan(p removalPlan) ([]byte, error) {
	if e := p.validate(); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	if len(raw) > maxRemovalPlanBytes {
		return nil, errors.New("removal plan exceeds metadata budget")
	}
	return raw, nil
}
func decodeRemovalPlan(raw []byte) (removalPlan, error) {
	var p removalPlan
	if len(raw) == 0 || len(raw) > maxRemovalPlanBytes {
		return p, errors.New("removal plan exceeds metadata budget")
	}
	// Canonical re-encoding rejects duplicate/omitted fields, null, escaped keys,
	// alternate numbers and whitespace. Input bytes and object count are bounded.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&p); e != nil {
		return p, e
	}
	canonical, e := encodeRemovalPlan(p)
	if e != nil {
		return p, e
	}
	if !bytes.Equal(raw, canonical) {
		return p, errors.New("noncanonical removal plan")
	}
	return p, nil
}

func validRemovalObjectPath(kind, name string) bool {
	if (kind == "core" || kind == "incoming") && strings.HasPrefix(name, "AccessWeaver.app/") {
		return validPath(strings.TrimPrefix(name, "AccessWeaver.app/"))
	}
	return validPath(name)
}
