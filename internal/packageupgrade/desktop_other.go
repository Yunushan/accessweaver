//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

import "errors"

func DesktopPackageOperation(phase string) (DesktopPackageResult, error) {
	return DesktopPackageResult{}, errors.New("desktop package inspection requires macOS")
}
