//go:build linux && (amd64 || arm64)

package managed

import (
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
)

const linuxPolicyParent = "/etc"
const linuxPolicyDirectory = "accessweaver"
const linuxPolicyFile = "installation.json"
const linuxPolicyLock = ".accessweaver-policy.lock"

func machinePolicySupported() bool { return true }
func readLinuxInstallation(dir *os.File, owner uint32, persistent bool) ([]byte, error) {
	if persistent {
		if err := linuxtrust.CheckPersistent(dir); err != nil {
			return nil, err
		}
	}
	file, err := linuxtrust.OpenRegularAt(dir, linuxPolicyFile, owner)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if persistent {
		if err := linuxtrust.CheckPersistent(file); err != nil {
			return nil, err
		}
	}
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() < 1 || before.Size() > MaxInstallationBytes {
		return nil, errors.New("machine installation must be bounded nonempty JSON")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxInstallationBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaxInstallationBytes || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(data)) != after.Size() {
		return nil, errors.New("machine installation changed during reading")
	}
	return data, nil
}
func readMachineInstallation() ([]byte, bool, error) {
	parent, err := openLinuxPolicyParent()
	if err != nil {
		return nil, true, err
	}
	defer parent.Close()
	dir, err := linuxtrust.OpenDirectoryAt(parent, linuxPolicyDirectory, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	defer dir.Close()
	data, err := readLinuxInstallation(dir, 0, true)
	return data, true, err
}

func openLinuxPolicyParent() (*os.File, error) {
	parent, err := linuxtrust.OpenRootDirectory(linuxPolicyParent)
	if err != nil {
		return nil, err
	}
	if err := linuxtrust.CheckPersistent(parent); err != nil {
		parent.Close()
		return nil, err
	}
	return parent, nil
}
