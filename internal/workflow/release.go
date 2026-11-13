package workflow

import (
	"errors"
	"regexp"
	"strings"
)

var semver = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

type VersionCheck struct {
	Version         string `json:"version"`
	CurrentVersion  string `json:"currentVersion"`
	UpdateAvailable bool   `json:"updateAvailable"`
}

// Compare numeric identifiers without machine-integer overflow.
func numericCompare(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}
func parseVersion(value string) []string {
	m := semver.FindStringSubmatch(value)
	if m == nil {
		return nil
	}
	for _, id := range strings.Split(m[4], ".") {
		if isNumeric(id) && len(id) > 1 && id[0] == '0' {
			return nil
		}
	}
	return m
}
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func compareVersion(a, b []string) int {
	for i := 1; i <= 3; i++ {
		if n := numericCompare(a[i], b[i]); n != 0 {
			return n
		}
	}
	if a[4] == b[4] {
		return 0
	}
	if a[4] == "" {
		return 1
	}
	if b[4] == "" {
		return -1
	}
	x, y := strings.Split(a[4], "."), strings.Split(b[4], ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		n := 0
		xn, yn := isNumeric(x[i]), isNumeric(y[i])
		switch {
		case xn && yn:
			n = numericCompare(x[i], y[i])
		case xn:
			n = -1
		case yn:
			n = 1
		default:
			n = strings.Compare(x[i], y[i])
		}
		if n != 0 {
			return n
		}
	}
	if len(x) < len(y) {
		return -1
	}
	if len(x) > len(y) {
		return 1
	}
	return 0
}
func CheckVersions(current string, candidates []string) (VersionCheck, error) {
	return checkVersions(current, candidates, false)
}

// CheckReleaseVersions keeps stable installations on stable releases. A
// prerelease installation can still discover newer prereleases and stable releases.
func CheckReleaseVersions(current string, candidates []string) (VersionCheck, error) {
	return checkVersions(current, candidates, true)
}

func checkVersions(current string, candidates []string, followChannel bool) (VersionCheck, error) {
	base := parseVersion(current)
	if base == nil {
		return VersionCheck{}, errors.New("invalid current semantic version")
	}
	var best []string
	var tag string
	stableOnly := followChannel && base[4] == ""
	prereleaseSeen := false
	for _, candidate := range candidates {
		parsed := parseVersion(candidate)
		if parsed == nil {
			continue
		}
		if stableOnly && parsed[4] != "" {
			prereleaseSeen = true
			continue
		}
		if best == nil || compareVersion(parsed, best) > 0 {
			best = parsed
			tag = candidate
		}
	}
	if best == nil {
		if prereleaseSeen {
			return VersionCheck{CurrentVersion: current}, nil
		}
		return VersionCheck{}, errors.New("no published semantic release version found")
	}
	return VersionCheck{tag, current, compareVersion(best, base) > 0}, nil
}
