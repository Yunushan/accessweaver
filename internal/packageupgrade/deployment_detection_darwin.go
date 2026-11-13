//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"errors"
	"os"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/darwintrust"
)

// DetectDeployment verifies the active bundle against this package helper's
// compiled seal. It acquires the shared runtime lease and starts no process.
func DetectDeployment() (DeploymentDetection, error) {
	seal, err := compiledDeploymentIdentity()
	if err != nil {
		return DeploymentDetection{}, err
	}
	if _, present := os.LookupEnv(runtimeLeaseEnvironment); present {
		return DeploymentDetection{}, errors.New("runtime descriptor supplied to deployment detector")
	}
	parent, err := darwintrust.OpenRootDirectory(deploymentParent)
	if err != nil {
		return DeploymentDetection{}, errors.New("cannot inspect deployment authority")
	}
	r := nativeRuntimeReads()
	expectedBuild := buildinfo.Current()
	different := false
	lease, err := acquireInstalledRuntimeScope(parent, r, func(root *os.File, lease *RuntimeLease) error {
		active, build, err := r.readActiveRuntime(root, "")
		if err != nil {
			return err
		}
		if err = r.sameDeploymentEntry(parent, deploymentRoot, root, 0); err != nil {
			return err
		}
		if err = r.sameRuntimeFile(root, lease.file, 0); err != nil {
			return err
		}
		different = active.Identity != seal || build != expectedBuild
		return nil
	})
	if err != nil {
		return DeploymentDetection{}, errors.New("cannot verify an active protected deployment")
	}
	if err = r.finishLease(lease, nil); err != nil {
		return DeploymentDetection{}, errors.New("cannot complete deployment inspection")
	}
	if different {
		return DeploymentDetection{}, errors.New("active deployment differs from the approved package seal")
	}
	return DeploymentDetection{
		SchemaVersion:  1,
		Build:          expectedBuild,
		ManifestSHA256: seal.ManifestSHA256,
		PayloadSHA256:  seal.PayloadSHA256,
	}, nil
}
