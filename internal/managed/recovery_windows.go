//go:build windows

package managed

import (
	"crypto/ed25519"
	"time"
)

func applyMachineRecovery(data []byte, key ed25519.PublicKey, minimum uint64) (InstallResult, error) {
	if err := requirePolicyAdministrator(); err != nil {
		return InstallResult{}, err
	}
	tx, err := beginMachineInstallation(false)
	if err != nil {
		return InstallResult{}, err
	}
	return commitRecovery(tx, data, key, minimum, time.Now)
}
