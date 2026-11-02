//go:build darwin && (amd64 || arm64)

package nativepath

import "errors"

func SystemDirectory() (string, error) { return "", errors.New("Windows system paths require Windows") }
func ProgramData() (string, error)     { return "", errors.New("Windows shared storage requires Windows") }

// A managed child inherits no caller-selected loader/runtime/search settings.
// This environment does not turn a vendor executable into a process sandbox.
func ProcessEnvironment() ([]string, error) {
	return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "TZ=UTC"}, nil
}
func UtilityEnvironment() ([]string, error) {
	return nil, errors.New("native Windows utility environment is unavailable")
}
