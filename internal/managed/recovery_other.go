//go:build !windows && ((!linux && !darwin) || (!amd64 && !arm64))

package managed

import (
	"crypto/ed25519"
)

func applyMachineRecovery(data []byte, key ed25519.PublicKey, minimum uint64) (InstallResult, error) {
	return InstallResult{}, ErrUnsupported
}
