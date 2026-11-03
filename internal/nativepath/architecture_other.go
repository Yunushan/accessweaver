//go:build !windows

package nativepath

import "errors"

func WindowsArchitecture() (string, error) {
	return "", errors.New("Windows architecture requires Windows")
}
