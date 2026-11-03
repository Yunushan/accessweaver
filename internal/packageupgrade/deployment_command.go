package packageupgrade

import (
	"errors"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
)

// Set only by the native packaging build after the complete incoming bundle
// is sealed. Empty defaults refuse. No flag, environment or installed app can
// select these identities or an input/output path.
var sealedVersion string
var sealedManifestSHA256 string
var sealedPayloadSHA256 string

type DeploymentResult struct {
	SchemaVersion                   int    `json:"schemaVersion"`
	Operation                       string `json:"operation"`
	Generation                      uint64 `json:"generation"`
	Version                         string `json:"version"`
	ManifestSHA256                  string `json:"manifestSHA256"`
	PayloadSHA256                   string `json:"payloadSHA256"`
	SlotID                          string `json:"slotID"`
	State                           string `json:"state"`
	OperationRecordPublished        bool   `json:"operationRecordPublished"`
	PublisherSignatureVerified      bool   `json:"publisherSignatureVerified"`
	ProductionQualificationComplete bool   `json:"productionQualificationComplete"`
}

func validDeploymentOperation(op string) bool {
	return op == "prepare-deployment" || op == "activate-deployment" || op == "deactivate-deployment" || op == "abandon-deployment"
}
func compiledDeploymentIdentity() (deploymentIdentity, error) {
	i := deploymentIdentity{sealedVersion, sealedManifestSHA256, sealedPayloadSHA256}
	if e := i.validate(); e != nil {
		return i, errors.New("deployment helper has no valid compiled payload seal")
	}
	build := buildinfo.Current()
	if build.Version != i.Version || build.SourceState != "clean" || !source.MatchString(build.Commit) {
		return i, errors.New("deployment helper build identity is not a sealed clean release")
	}
	return i, nil
}
