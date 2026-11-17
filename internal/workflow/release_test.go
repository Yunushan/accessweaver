package workflow

import "testing"

func TestReleaseSelection(t *testing.T) {
	for _, tc := range []struct {
		current  string
		tags     []string
		selected string
		newer    bool
	}{
		{"0.1.0-alpha", []string{"v0.1.0-alpha"}, "v0.1.0-alpha", false},
		{"0.1.0-alpha", []string{"v0.0.9", "v0.1.0", "v0.1.0-alpha.9"}, "v0.1.0", true},
		{"1.0.0-rc.2", []string{"1.0.0-rc.10", "1.0.0-rc.3"}, "1.0.0-rc.10", true},
		{"1.0.0", []string{"1.0.0+build.2", "invalid-tag", "1.0.0-rc.999"}, "1.0.0+build.2", false},
		{"2.0.0", []string{"1.999999999999999999999.0", "0.1.0"}, "1.999999999999999999999.0", false},
	} {
		got, err := CheckVersions(tc.current, tc.tags)
		if err != nil || got.Version != tc.selected || got.UpdateAvailable != tc.newer {
			t.Fatalf("%+v: %+v %v", tc, got, err)
		}
	}
	for _, tag := range []string{"release", "1.0", "01.0.0", "1.0.0-01"} {
		if _, err := CheckVersions("0.1.0-alpha", []string{tag}); err == nil {
			t.Fatalf("invalid version accepted: %s", tag)
		}
	}
}

func TestReleaseSelectionFollowsInstalledChannel(t *testing.T) {
	tags := []string{"v2.0.0-rc.1", "v1.9.0+build.3", "v1.8.0", "unversioned"}
	for _, tc := range []struct {
		current, want string
		update        bool
	}{
		{"1.8.0", "v1.9.0+build.3", true},
		{"1.9.0+build.2", "v1.9.0+build.3", false},
		{"1.9.1", "v1.9.0+build.3", false},
		{"1.9.0-rc.1", "v2.0.0-rc.1", true},
		{"2.0.0-rc.1", "v2.0.0-rc.1", false},
	} {
		got, err := CheckReleaseVersions(tc.current, tags)
		if err != nil || got.Version != tc.want || got.CurrentVersion != tc.current || got.UpdateAvailable != tc.update {
			t.Fatalf("current %s: got %+v, err %v", tc.current, got, err)
		}
	}
	got, err := CheckReleaseVersions("1.0.0", []string{"v2.0.0-rc.1"})
	if err != nil || got.Version != "" || got.CurrentVersion != "1.0.0" || got.UpdateAvailable {
		t.Fatalf("expected no compatible release from a prerelease-only list, got %+v, err %v", got, err)
	}
	got, err = CheckReleaseVersions("2.0.0-rc.1", []string{"v2.0.0"})
	if err != nil || !got.UpdateAvailable || got.Version != "v2.0.0" {
		t.Fatalf("expected prerelease to discover stable release, got %+v, err %v", got, err)
	}
}
