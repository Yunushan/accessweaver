//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

import "errors"

func ProductPackageOperation(phase string) (ProductPackageResult, error) {
	return ProductPackageResult{}, errors.New("product package coordination requires macOS")
}
