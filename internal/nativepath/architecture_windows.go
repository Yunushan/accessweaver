//go:build windows

package nativepath

import "golang.org/x/sys/windows"

// WindowsArchitecture reports the host OS, including when this process is
// emulated. Caller environment variables and the process build target are not
// authoritative for selecting kernel driver packages.
func WindowsArchitecture() (string, error) {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err != nil {
		return "", err
	}
	return windowsMachineArchitecture(native)
}
