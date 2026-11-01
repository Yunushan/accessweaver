//go:build !windows

package managed

func machinePolicySupported() bool                   { return false }
func readMachineInstallation() ([]byte, bool, error) { return nil, false, nil }
