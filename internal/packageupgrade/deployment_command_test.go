package packageupgrade

import (
	"strings"
	"testing"
)

func TestDeploymentHelperHasNoRuntimeSealOverride(t *testing.T) {
	// Ordinary builds carry empty defaults. Merely selecting a known operation
	// cannot create a payload seal or change the fixed input/output authority.
	t.Setenv("ACCESSWEAVER_DEPLOYMENT_MANIFEST_SHA256", strings.Repeat("a", 64))
	t.Setenv("ACCESSWEAVER_DEPLOYMENT_PAYLOAD_SHA256", strings.Repeat("b", 64))
	if _, e := compiledDeploymentIdentity(); e == nil {
		t.Fatal("unsealed helper accepted")
	}
	for _, op := range []string{"prepare-deployment", "activate-deployment", "deactivate-deployment", "abandon-deployment"} {
		if !validDeploymentOperation(op) {
			t.Fatal(op)
		}
	}
	for _, op := range []string{"", "prepare-deployment /tmp/input", "activate-deployment --path=/tmp/input", "status", "PREPARE-DEPLOYMENT"} {
		if validDeploymentOperation(op) {
			t.Fatal("unrecognized command accepted", op)
		}
	}
}
