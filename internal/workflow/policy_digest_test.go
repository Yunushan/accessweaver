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
