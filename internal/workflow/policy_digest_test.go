package workflow

import "testing"

func TestPolicyDigestBindsWorkflowAndRejectsInvalidRequest(t *testing.T) {
	first := Request{Action: "dns", DNS: "doh"}
	a, err := first.PolicyDigest()
	if err != nil {
		t.Fatal(err)
	}
	second := Request{Action: "dns", DNS: "dnscrypt"}
	b, err := second.PolicyDigest()
	if err != nil || a == b {
		t.Fatal("DNS operation parameters not bound", err)
	}
	if _, err := (Request{Action: "unknown"}).PolicyDigest(); err == nil {
		t.Fatal("invalid workflow received approval digest")
	}
}

func TestWorkflowDigestVersionOneCompatibility(t *testing.T) {
	digest, err := (Request{Action: "dns", DNS: "doh"}).PolicyDigest()
	if err != nil || digest != "e269846228db05c31677239f253b48798b5fa1220aa9b9c4f6f6185d364c6b12" {
		t.Fatal("version-one workflow approval digest changed", digest, err)
	}
}
