package managed

import (
	"errors"
	"fmt"

	"github.com/Yunushan/accessweaver/internal/nativepath"
)

// Guard is injected only by in-process constructors, never by API/configuration
// input. A nil loader always uses the fixed protected native source.
type Guard struct {
	load    func() (*Authority, error)
	protect func(string, string, bool) error
}

func NewGuard(load func() (*Authority, error)) *Guard {
	return &Guard{load: load, protect: checkProtectedInput}
}
func (g *Guard) authority() (*Authority, error) {
	if g == nil || g.load == nil {
		return Current()
	}
	return g.load()
}
func (g *Guard) ProfileChanges() error {
	a, err := g.authority()
	if err != nil {
		return err
	}
	if a != nil && !a.verified.Policy.AllowProfileChanges {
		return fmt.Errorf("%w: profile changes are disabled", ErrDenied)
	}
	return nil
}
func (g *Guard) Diagnostics() error {
	a, err := g.authority()
	if err != nil {
		return err
	}
	if a != nil && !a.verified.Policy.AllowDiagnostics {
		return fmt.Errorf("%w: network diagnostics are disabled", ErrDenied)
	}
	return nil
}

type LaunchRequest struct {
	RawArguments                            bool
	Engine, InputSHA256, Binary, ConfigPath string
	GeneratedInputs                         bool
}

func (g *Guard) Launch(input LaunchRequest) error {
	a, err := g.authority()
	if err != nil {
		return err
	}
	return g.launchAuthority(a, input)
}
func (g *Guard) LaunchEnvironment(input LaunchRequest) ([]string, error) {
	a, err := g.authority()
	if err != nil {
		return nil, err
	}
	if err := g.launchAuthority(a, input); err != nil {
		return nil, err
	}
	if a == nil {
		return nil, nil
	}
	return nativepath.ProcessEnvironment()
}
func (g *Guard) launchAuthority(a *Authority, input LaunchRequest) error {
	if a == nil {
		return nil
	}

	for _, rule := range a.verified.Policy.Launches {
		if rule.Engine != input.Engine || rule.InputSHA256 != input.InputSHA256 {
			continue
		}
		// User-owned generated files cannot become administrator-trusted inputs.
		// A broker must stage and authorize them before managed use is enabled.
		if input.RawArguments {
			return fmt.Errorf("%w: managed native-argument asset validation is not implemented", ErrDenied)
		}
		if input.GeneratedInputs {
			return fmt.Errorf("%w: protected generated-input staging is not implemented", ErrDenied)
		}
		if err := g.protected(input.Binary, rule.BinarySHA256, false); err != nil {
			return err
		}
		if input.ConfigPath != "" {
			if rule.ConfigSHA256 == "" {
				return fmt.Errorf("%w: configuration contents are not pinned", ErrDenied)
			}
			if err := g.protected(input.ConfigPath, rule.ConfigSHA256, false); err != nil {
				return err
			}
		} else if rule.ConfigSHA256 != "" {
			return fmt.Errorf("%w: approved configuration is missing", ErrDenied)
		}
		return nil
	}
	return fmt.Errorf("%w: launch inputs are not approved", ErrDenied)
}

func (g *Guard) protected(path, digest string, directory bool) error {
	check := checkProtectedInput
	if g != nil && g.protect != nil {
		check = g.protect
	}
	if err := check(path, digest, directory); err != nil {
		return fmt.Errorf("%w: protected input check failed: %w", ErrDenied, err)
	}
	return nil
}

type WorkflowPermission struct {
	Managed, AllowDownloads bool
	Downloads               []DownloadRule
}
type InputPath struct {
	Path      string
	Directory bool
}

func (g *Guard) Workflow(action, digest string, paths []InputPath) (WorkflowPermission, error) {
	a, err := g.authority()
	if err != nil {
		return WorkflowPermission{}, err
	}
	if a == nil {
		return WorkflowPermission{AllowDownloads: true}, nil
	}
	for _, rule := range a.verified.Policy.Workflows {
		if rule.Action != action || rule.InputSHA256 != digest {
			continue
		}
		for _, input := range paths {
			if input.Path != "" {
				if err := g.protected(input.Path, "", input.Directory); err != nil {
					return WorkflowPermission{}, err
				}
			}
		}
		return WorkflowPermission{Managed: true, AllowDownloads: a.verified.Policy.AllowDownloads, Downloads: append([]DownloadRule{}, a.verified.Policy.Downloads...)}, nil
	}
	return WorkflowPermission{}, fmt.Errorf("%w: workflow request is not approved", ErrDenied)
}

// Existing service configurations have no signed service-input rule format yet.
// An enrolled machine must never bypass policy through the service-host command.
func (g *Guard) ServiceHost() error {
	a, err := g.authority()
	if err != nil {
		return err
	}
	if a != nil {
		return fmt.Errorf("%w: signed service-host authorization is not implemented", ErrDenied)
	}
	return nil
}

func IsPolicyError(err error) bool {
	return errors.Is(err, ErrDenied) || errors.Is(err, ErrUnavailable)
}
