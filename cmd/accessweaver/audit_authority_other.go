//go:build !linux && !windows

package main

func auditAuthorityFilePaths() []string { return nil }
