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
