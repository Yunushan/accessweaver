//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

import "errors"

// DeploymentOperation refuses outside the two supported native Mac targets.
func DeploymentOperation(op string) (DeploymentResult, error) {
	return DeploymentResult{}, errors.New("native deployment operations require macOS amd64 or arm64")
}
