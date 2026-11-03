//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

import "errors"

func PackageOperation(phase string) (DeploymentResult, error) {
	return DeploymentResult{}, errors.New("native package operations require macOS amd64 or arm64")
}
