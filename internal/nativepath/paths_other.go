//go:build !windows

package nativepath

import "errors"

func SystemDirectory() (string, error) { return "", errors.New("Windows system paths require Windows") }
func ProgramData() (string, error)     { return "", errors.New("Windows known folders require Windows") }
func ProcessEnvironment() ([]string, error) {
	return nil, errors.New("native managed environment is unavailable on this platform")
}

func UtilityEnvironment() ([]string, error) {
	return nil, errors.New("native Windows utility environment is unavailable")
}
