package profile

import (
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
)

func TestLaunchDigestBindsExecutionInputsWithoutDisplayMetadata(t *testing.T) {
	p := New("first-profile", "First label", "byedpi")
	digest, err := p.ExecutionDigest()
	if err != nil {
		t.Fatal(err)
	}
	p.ID = "other-profile"
	p.Name = "Other label"
	p.Notes = "Private notes"
	p.Description = "Private description"
	p.UpdatedAt = time.Now()
	p.Probe.Host = "example.org"
	same, err := p.ExecutionDigest()
	if err != nil || same != digest {
		t.Fatal("display metadata changed execution digest", err)
	}
	p.Args = nil
	p.Routing.Applications = nil
	same, err = p.ExecutionDigest()
	if err != nil || same != digest {
		t.Fatal("empty representation changed execution digest", err)
	}
	p.Args = []string{"--disorder", "1"}
	changed, err := p.ExecutionDigest()
	if err != nil || changed == digest {
		t.Fatal("arguments not bound", err)
	}
	p.Args = nil
	p.Routing.IncludeDomains = []string{"example.org"}
	changed, err = p.ExecutionDigest()
	if err != nil || changed == digest {
		t.Fatal("routing inputs not bound", err)
	}
	p.Routing.IncludeDomains = nil
	p.ConfigPath = "/private/config.json"
	changed, err = p.ExecutionDigest()
	if err != nil || changed == digest {
		t.Fatal("configuration reference not bound", err)
	}
	p.ConfigPath = ""
	p.Binary = "/trusted/ciadpi"
	changed, err = p.ExecutionDigest()
	if err != nil || changed == digest {
		t.Fatal("executable reference not bound", err)
	}
	launch, err := managed.InputDigest("launch", map[string]string{"action": "dns"})
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := managed.InputDigest("workflow", map[string]string{"action": "dns"})
	if err != nil || launch == workflow {
		t.Fatal("input digest purposes overlap", err)
	}
}

func TestExecutionDigestVersionOneCompatibility(t *testing.T) {
	p := New("golden-profile", "Golden", "byedpi")
	p.Binary = "/trusted/ciadpi"
	p.SHA256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	p.Args = []string{"--disorder", "1"}
	p.Routing.IncludeDomains = []string{"example.org"}
	p.Probe.Host = "example.org"
	digest, err := p.ExecutionDigest()
	if err != nil || digest != "0a26850c5d9efdfef58c9ef719d24789f8133cf37799358d8e9ce620a6d23eb7" {
		t.Fatal("version-one approval digest changed", digest, err)
	}
}
