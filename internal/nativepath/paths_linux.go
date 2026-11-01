//go:build linux && (amd64 || arm64)

package nativepath

import "errors"

func SystemDirectory() (string, error) { return "", errors.New("Windows system paths require Windows") }
func ProgramData() (string, error)     { return "", errors.New("Windows shared storage requires Windows") }

// Managed Linux engines inherit no caller-selected runtime, loader, shell,
// configuration or search-path variables. Vendor behavior still needs native
// qualification; this environment is not a process sandbox.
func ProcessEnvironment() ([]string, error) {
	return []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}, nil
}
func UtilityEnvironment() ([]string, error) {
	return nil, errors.New("native Windows utility environment is unavailable")
}
