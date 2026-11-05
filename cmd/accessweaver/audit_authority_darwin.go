//go:build darwin

package main

// Darwin policy authority uses these fixed protected native locations.
func auditAuthorityFilePaths() []string {
	return []string{"/Library/Preferences/AccessWeaver/installation.json", "/Library/Preferences/AccessWeaver/acceptance.json", "/Library/Preferences/.accessweaver-policy.lock"}
}
