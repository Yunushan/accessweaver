//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

import "errors"

// DeploymentOperation refuses outside the two supported native Mac targets.
func DeploymentOperation(op string) (DeploymentResult, error) {
	return DeploymentResult{}, errors.New("native deployment operations require macOS amd64 or arm64")
}

// DetectDeployment requires the native macOS deployment authority.
func DetectDeployment() (DeploymentDetection, error) {
	return DeploymentDetection{}, errors.New("native deployment detection requires macOS amd64 or arm64")
}
