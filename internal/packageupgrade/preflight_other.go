//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

import "errors"

func Preflight(incoming string) (Result, error) {
	return Result{}, errors.New("native macOS upgrade preflight is unavailable on this platform")
}
