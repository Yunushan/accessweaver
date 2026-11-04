package packageupgrade

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func removalPlanFixture() removalPlan {
	active := deploymentFixtureSlot(1, "0.1.1-alpha")
	nonce := uint64(100)
	object := func(name, kind, seal string) removalPlanObject {
		nonce++
		o := removalPlanObject{Path: name, Kind: kind, Mode: "0755", Device: 1, Inode: nonce}
		if kind == "file" {
			o.Mode = "0644"
			o.Bytes = 1
			o.SHA256 = seal
			o.MtimeNs = 1000
			o.CtimeNs = 1001
		}
		return o
	}
	root := func(kind, key string, identity deploymentIdentity) removalPlanRoot {
		return removalPlanRoot{Kind: kind, Key: key, Identity: identity, ParentDevice: 1, ParentInode: 999999, Objects: []removalPlanObject{object(".", "directory", "")}}
	}
	core := root("core", active.ID, active.Identity)
	core.Objects[0].Inode = active.Inode
	core.Objects = append(core.Objects, object("AccessWeaver.app", "directory", ""), object("AccessWeaver.app/file", "file", strings.Repeat("f", 64)))
	incoming := root("incoming", active.Identity.ManifestSHA256, active.Identity)
	incoming.Objects = append(incoming.Objects, object("AccessWeaver.app", "directory", ""), object("AccessWeaver.app/file", "file", strings.Repeat("f", 64)))
	public := root("public", "AccessWeaver.app", deploymentIdentity{})
	public.Objects = append(public.Objects, object("-first", "file", strings.Repeat("f", 64)))
	seal := strings.Repeat("d", 64)
	registry := root("registrations", desktopRoot, deploymentIdentity{})
	registry.Objects = append(registry.Objects, object("desktop-"+seal+".json", "file", seal))
	receipts := root("receipts", "receipts", deploymentIdentity{})
	for _, id := range []string{removalCoreReceiptID, desktopBundleID, desktopBundleID + ".registration." + seal} {
		for _, ext := range []string{".plist", ".bom"} {
			receipts.Objects = append(receipts.Objects, object(id+ext, "file", strings.Repeat("e", 64)))
		}
	}
	sort.Slice(receipts.Objects[1:], func(i, j int) bool { return receipts.Objects[1+i].Path < receipts.Objects[1+j].Path })
	p := removalPlan{1, 7, active, seal, []removalPlanRoot{core, incoming, public, registry, receipts}}
	sort.Slice(p.Roots, func(i, j int) bool {
		return p.Roots[i].Kind+"\x00"+p.Roots[i].Key < p.Roots[j].Kind+"\x00"+p.Roots[j].Key
	})
	return p
}
func TestRemovalPlanCanonicalFullRolesAndBindings(t *testing.T) {
	p := removalPlanFixture()
	raw, e := encodeRemovalPlan(p)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := decodeRemovalPlan(raw)
	if e != nil {
		t.Fatal(e)
	}
	roundtrip, e := encodeRemovalPlan(decoded)
	if e != nil || !bytes.Equal(raw, roundtrip) {
		t.Fatal("plan roundtrip differs", e)
	}
	for _, kind := range []string{"scope", "missing-role", "duplicate-root", "root-order", "active-inode", "incoming-seal", "unknown-object", "cross-device", "duplicate-vnode", "missing-parent", "alias-path", "traversal", "absolute", "file-mode", "directory-hash", "negative-bytes", "bad-hash", "registration-seal", "extra-receipt", "missing-receipt", "selected-registration", "object-order", "object-capacity"} {
		t.Run(kind, func(t *testing.T) {
			changed := removalPlanFixture()
			core := &changed.Roots[0]
			incoming := &changed.Roots[1]
			public := &changed.Roots[2]
			receipts := &changed.Roots[3]
			registry := &changed.Roots[4]
			switch kind {
			case "scope":
				public.Kind = "profiles"
			case "missing-role":
				changed.Roots = changed.Roots[:4]
			case "duplicate-root":
				changed.Roots = append(changed.Roots, changed.Roots[4])
			case "root-order":
				changed.Roots[0], changed.Roots[1] = changed.Roots[1], changed.Roots[0]
			case "active-inode":
				core.Objects[0].Inode++
			case "incoming-seal":
				incoming.Identity.PayloadSHA256 = strings.Repeat("c", 64)
			case "unknown-object":
				public.Objects[1].Kind = "symlink"
			case "cross-device":
				public.Objects[1].Device++
			case "duplicate-vnode":
				public.Objects[1].Inode = core.Objects[0].Inode
			case "missing-parent":
				public.Objects[1].Path = "absent/file"
			case "alias-path":
				public.Objects = append(public.Objects, public.Objects[1])
				public.Objects[2].Path = "-FIRST"
			case "traversal":
				public.Objects[1].Path = "../file"
			case "absolute":
				public.Objects[1].Path = "/tmp/file"
			case "file-mode":
				public.Objects[1].Mode = "06755"
			case "directory-hash":
				public.Objects[0].SHA256 = strings.Repeat("f", 64)
			case "negative-bytes":
				public.Objects[1].Bytes = -1
			case "bad-hash":
				public.Objects[1].SHA256 = "not-a-seal"
			case "registration-seal":
				registry.Objects[1].SHA256 = strings.Repeat("b", 64)
			case "extra-receipt":
				extra := receipts.Objects[len(receipts.Objects)-1]
				extra.Path = "unrelated.plist"
				extra.Inode = 200000
				receipts.Objects = append(receipts.Objects, extra)
			case "missing-receipt":
				receipts.Objects = receipts.Objects[:len(receipts.Objects)-1]
			case "selected-registration":
				changed.DesktopRecordSHA256 = strings.Repeat("a", 64)
			case "object-order":
				core.Objects[1], core.Objects[2] = core.Objects[2], core.Objects[1]
			case "object-capacity":
				public.Objects = make([]removalPlanObject, MaxFiles+5)
			}
			malformed, _ := json.Marshal(changed)
			if _, e := decodeRemovalPlan(malformed); e == nil {
				t.Fatal("unsafe plan accepted")
			}
		})
	}
	for name, data := range map[string][]byte{
		"unknown":    append([]byte("{\"callerPath\":\"/tmp\","), raw[1:]...),
		"duplicate":  append([]byte("{\"schemaVersion\":1,"), raw[1:]...),
		"null":       bytes.Replace(raw, []byte("\"mtimeNs\":0"), []byte("\"mtimeNs\":null"), 1),
		"omitted":    bytes.Replace(raw, []byte("\"mtimeNs\":0,"), nil, 1),
		"whitespace": append([]byte(" "), raw...),
		"trailing":   append(append([]byte{}, raw...), []byte("{}")...),
		"exponent":   bytes.Replace(raw, []byte("\"generation\":7"), []byte("\"generation\":7e0"), 1),
		"empty":      nil,
		"oversize":   bytes.Repeat([]byte(" "), maxRemovalPlanBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeRemovalPlan(data); e == nil {
				t.Fatal("noncanonical plan accepted")
			}
		})
	}
}
func TestRemovalPlanMetadataBudgetAndMaximumContainerDepth(t *testing.T) {
	p := removalPlanFixture()
	core := &p.Roots[0]
	prefix := "AccessWeaver.app"
	// Container prefix is fixed and does not consume the manifest's 32 levels.
	for n := 0; n < 31; n++ {
		prefix += "/d"
		core.Objects = append(core.Objects, removalPlanObject{Path: prefix, Kind: "directory", Mode: "0755", Device: 1, Inode: uint64(20000 + n)})
	}
	core.Objects = append(core.Objects, removalPlanObject{Path: prefix + "/f", Kind: "file", Mode: "0644", Device: 1, Inode: 30000, SHA256: strings.Repeat("f", 64)})
	sort.Slice(core.Objects[1:], func(i, j int) bool { return core.Objects[i+1].Path < core.Objects[j+1].Path })
	if _, e := encodeRemovalPlan(p); e != nil {
		t.Fatal("maximum manifest depth rejected", e)
	}
	p = removalPlanFixture()
	public := &p.Roots[2]
	for n := 0; n < 600; n++ {
		public.Objects = append(public.Objects, removalPlanObject{Path: strings.Repeat("a", 3990) + fmt.Sprintf("%04d", n), Kind: "file", Mode: "0644", Device: 1, Inode: uint64(40000 + n), SHA256: strings.Repeat("f", 64)})
	}
	sort.Slice(public.Objects[1:], func(i, j int) bool { return public.Objects[i+1].Path < public.Objects[j+1].Path })
	if _, e := encodeRemovalPlan(p); e == nil {
		t.Fatal("oversized serialized plan accepted")
	}
}
