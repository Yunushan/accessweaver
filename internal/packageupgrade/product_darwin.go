//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"errors"
	"os"
)

// ProductPackageOperation coordinates Apple's batched pre/copy/post phases.
// Apple Installer alone writes public payloads. Core preparation/activation
// reuse the existing fixed authority, exclusive leases, seals and generation
// fences; repeated component phases reconcile the same prepared/active identity.
// Failures preserve state, including publication that preceded an error.
func ProductPackageOperation(phase string) (ProductPackageResult, error) {
	var result ProductPackageResult
	if phase != "preinstall" && phase != "postinstall" {
		return result, errors.New("unknown product package phase")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return result, errors.New("product package coordination requires root")
	}
	if _, e := compiledProductIdentity(); e != nil {
		return result, e
	}
	result.SchemaVersion = 1
	result.Phase = phase
	var e error
	// Pre checks the existing registered app, aliases and downgrade history.
	// Post requires the new sealed record and full public app before activation.
	// The new record cannot be required in pre: Installer has not copied it.
	result.Desktop, e = desktopPackageOperation(phase, true)
	if e != nil {
		return result, e
	}
	result.Core, e = PackageOperation(phase)
	if e != nil {
		return result, e
	}
	if phase == "postinstall" {
		e = desktopCoreActive()
	}
	return result, e
}
