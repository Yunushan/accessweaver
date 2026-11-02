//go:build darwin && (amd64 || arm64)

package managed

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

const darwinPolicyParent = "/Library/Preferences"

func machinePolicySupported() bool { return true }
func openDarwinPolicyParent() (*os.File, error) {
	return darwintrust.OpenRootDirectory(darwinPolicyParent)
}
func readMachineSnapshot() (machineSnapshot, error) {
	parent, err := openDarwinPolicyParent()
	if err != nil {
		return machineSnapshot{present: true}, err
	}
	defer parent.Close()
	return readDarwinSnapshotAt(parent, 0)
}
func readMachineInstallation() ([]byte, bool, error) {
	snapshot, err := readMachineSnapshot()
	return snapshot.source, snapshot.present, err
}
func applyMachinePolicy(data []byte, key ed25519.PublicKey, change policyChange) (InstallResult, error) {
	if os.Geteuid() != 0 {
		return InstallResult{}, fmt.Errorf("%w: machine policy changes require a separately elevated root CLI", ErrDenied)
	}
	parent, err := openDarwinPolicyParent()
	if err != nil {
		return InstallResult{}, err
	}
	tx, err := beginDarwinInstallation(parent, change == changeInstall, 0)
	if err != nil {
		return InstallResult{}, err
	}
	return commitInstallation(tx, data, key, change, time.Now)
}
func applyMachineRecovery(data []byte, key ed25519.PublicKey, minimum uint64) (InstallResult, error) {
	if os.Geteuid() != 0 {
		return InstallResult{}, fmt.Errorf("%w: recovery requires a separately elevated root CLI", ErrDenied)
	}
	parent, err := openDarwinPolicyParent()
	if err != nil {
		return InstallResult{}, err
	}
	tx, err := beginDarwinInstallation(parent, false, 0)
	if err != nil {
		return InstallResult{}, err
	}
	return commitRecovery(tx, data, key, minimum, time.Now)
}
