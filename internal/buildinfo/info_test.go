package buildinfo

import (
	"runtime"
	"testing"
)

func TestExplicitReleaseIdentity(t *testing.T) {
	version, commit, state, built := Version, Commit, SourceState, BuiltAt
	t.Cleanup(func() { Version, Commit, SourceState, BuiltAt = version, commit, state, built })
	Version, Commit, SourceState, BuiltAt = "2.3.4-rc.1", "fixture-source", "modified", "2026-11-01T00:00:00Z"
	info := Current()
	if info.Version != Version || info.Commit != Commit || info.SourceState != SourceState || info.BuiltAt != BuiltAt || info.Platform != runtime.GOOS || info.Arch != runtime.GOARCH || info.GoVersion != runtime.Version() {
		t.Fatalf("inconsistent identity: %+v", info)
	}
}
