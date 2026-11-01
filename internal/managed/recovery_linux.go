//go:build linux && (amd64 || arm64)

package managed

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"
)

func applyMachineRecovery(data []byte, key ed25519.PublicKey, minimum uint64) (InstallResult, error) {
	if os.Geteuid() != 0 {
		return InstallResult{}, fmt.Errorf("%w: recovery requires a separately elevated root CLI", ErrDenied)
	}
	parent, err := openLinuxPolicyParent()
	if err != nil {
		return InstallResult{}, err
	}
	tx, err := beginLinuxInstallation(parent, false, 0)
	if err != nil {
		return InstallResult{}, err
	}
	tx.persistent = true
	return commitRecovery(tx, data, key, minimum, time.Now)
}
