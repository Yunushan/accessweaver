//go:build linux

package main

// Linux policy authority occupies only these fixed native locations.
func auditAuthorityFilePaths() []string {
	return []string{"/etc/accessweaver/installation.json", "/etc/accessweaver/acceptance.json", "/etc/.accessweaver-policy.lock"}
}
