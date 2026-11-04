//go:build windows

package main

// Windows policy authority is the fixed native HKLM Installation/Acceptance
// registry state. There are no authority files to invent or probe here.
func auditAuthorityFilePaths() []string { return nil }
