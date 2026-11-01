//go:build !windows

package managed

import "crypto/ed25519"

func applyMachinePolicy([]byte, ed25519.PublicKey, policyChange) (InstallResult, error) {
	return InstallResult{}, ErrUnsupported
}
