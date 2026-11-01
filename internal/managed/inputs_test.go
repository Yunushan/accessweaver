package managed

import (
	"github.com/Yunushan/accessweaver/internal/profile"
	"testing"
	"time"
)

func TestLaunchDigestBindsExecutionInputsWithoutDisplayMetadata(t *testing.T) {
	p := profile.New("first-profile", "First label", "byedpi")
	digest, err := LaunchDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = "other-profile"
	p.Name = "Other label"
	p.Notes = "Private notes"
	p.Description = "Private description"
	p.UpdatedAt = time.Now()
	p.Probe.Host = "example.org"
	same, err := LaunchDigest(p)
	if err != nil || same != digest {
		t.Fatal("display metadata changed execution digest", err)
	}
	p.Args = nil
	p.Routing.Applications = nil
	same, err = LaunchDigest(p)
	if err != nil || same != digest {
		t.Fatal("empty representation changed execution digest", err)
	}
	p.Args = []string{"--disorder", "1"}
	changed, err := LaunchDigest(p)
	if err != nil || changed == digest {
		t.Fatal("arguments not bound", err)
	}
	p.Args = nil
	p.Routing.IncludeDomains = []string{"example.org"}
	changed, err = LaunchDigest(p)
	if err != nil || changed == digest {
		t.Fatal("routing inputs not bound", err)
	}
	p.Routing.IncludeDomains = nil
	p.ConfigPath = "/private/config.json"
	changed, err = LaunchDigest(p)
	if err != nil || changed == digest {
		t.Fatal("configuration reference not bound", err)
	}
	p.ConfigPath = ""
	p.Binary = "/trusted/ciadpi"
	changed, err = LaunchDigest(p)
	if err != nil || changed == digest {
		t.Fatal("executable reference not bound", err)
	}
	launch, err := InputDigest("launch", map[string]string{"action": "dns"})
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := InputDigest("workflow", map[string]string{"action": "dns"})
	if err != nil || launch == workflow {
		t.Fatal("input digest purposes overlap", err)
	}
}
