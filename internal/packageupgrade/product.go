package packageupgrade

import (
	"encoding/json"
	"errors"
	"github.com/Yunushan/accessweaver/internal/buildinfo"
)

// The product application helper carries BOTH desktop and core compiled seals.
// Neither ordinary component has sufficient seals to enter this protocol.
type ProductPackageResult struct {
	SchemaVersion                   int                  `json:"schemaVersion"`
	Phase                           string               `json:"phase"`
	Desktop                         DesktopPackageResult `json:"desktop"`
	Core                            DeploymentResult     `json:"core"`
	ProductionQualificationComplete bool                 `json:"productionQualificationComplete"`
}

func validateProductBinding(core deploymentIdentity, desktop buildinfo.Info, component string) error {
	if e := core.validate(); e != nil {
		return e
	}
	encoded, e := json.Marshal(desktop)
	if e != nil {
		return e
	}
	if _, e = decodeBuild(encoded, desktop.Arch); e != nil {
		return e
	}
	if component != "application" || core.Version != desktop.Version || (desktop.Arch != "amd64" && desktop.Arch != "arm64") {
		return errors.New("product helper requires matching core and desktop application identities")
	}
	return nil
}

func compiledProductIdentity() (deploymentIdentity, error) {
	core, e := compiledDeploymentIdentity()
	if e != nil {
		return core, e
	}
	desktop, component, _, e := compiledDesktopIdentity()
	if e != nil {
		return core, e
	}
	return core, validateProductBinding(core, desktop, component)
}
