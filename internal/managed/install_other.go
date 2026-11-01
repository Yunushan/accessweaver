//go:build !windows

package managed

import "crypto/ed25519"

func applyMachineInstallation([]byte, ed25519.PublicKey, bool) (InstallResult, error) {
	return InstallResult{}, ErrUnsupported
}
