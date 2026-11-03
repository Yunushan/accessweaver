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

func TestPackagePhasesCannotSelectAnotherVolumeOrInputPath(t *testing.T) {
	for _, phase := range []string{"preinstall", "postinstall"} {
		for _, args := range [][]string{nil, {"package.pkg", "location", "/Volumes/Other"}, {"package.pkg", "location", "/", "bad\x00arg"}, {"package.pkg", "location", "/", strings.Repeat("x", 4097)}} {
			if e := executeForName(phase, args); e == nil {
				t.Fatal("invalid package argument accepted", phase)
			}
		}
		// The default unsealed/user build refuses even correct phase shape.
		if e := executeForName(phase, []string{"package.pkg", "ignored-install-location", "/"}); e == nil {
			t.Fatal("unsealed package phase accepted", phase)
		}
	}
}
