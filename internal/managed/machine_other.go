//go:build !windows && (!linux || (!amd64 && !arm64))

package managed

func machinePolicySupported() bool                   { return false }
func readMachineInstallation() ([]byte, bool, error) { return nil, false, nil }
