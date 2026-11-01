package profile

import "github.com/Yunushan/accessweaver/internal/managed"

func (p Profile) ExecutionDigest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	return managed.LaunchDigest(managed.LaunchInput{Version: p.Version, Engine: p.Engine, Binary: p.Binary, ConfigPath: p.ConfigPath, SHA256: p.SHA256, Args: p.Args,
		Routing: managed.RoutingInput{IncludeDomains: p.Routing.IncludeDomains, ExcludeDomains: p.Routing.ExcludeDomains, Applications: p.Routing.Applications}})
}
