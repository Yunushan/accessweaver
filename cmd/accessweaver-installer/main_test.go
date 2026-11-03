package main

import (
	"strings"
	"testing"
)

func TestDeploymentCLIRefusesCallerPathsAndUnsealedOperation(t *testing.T) {
	for _, op := range []string{"prepare-deployment", "activate-deployment", "deactivate-deployment", "abandon-deployment"} {
		// The test/default build has no linked deployment seals. Known commands
		// must reach the platform/root/seal guard and cannot mutate anything.
		e := execute([]string{op})
		if e == nil || strings.Contains(e.Error(), "usage:") {
			t.Fatalf("default guard for %s: %v", op, e)
		}
		for _, extra := range []string{"/tmp/incoming", "--path=/tmp/incoming", "--manifest=" + strings.Repeat("a", 64)} {
			if e := execute([]string{op, extra}); e == nil || !strings.Contains(e.Error(), "usage:") {
				t.Fatalf("caller override reached deployment operation: %v", e)
			}
		}
	}
}
