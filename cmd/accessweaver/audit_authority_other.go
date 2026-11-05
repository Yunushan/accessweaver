//go:build !linux && !windows && !darwin

package main

func auditAuthorityFilePaths() []string { return nil }
