// Package servicehost runs a foreground engine under the Windows SCM.
package servicehost

import (
	"errors"
	"io"
	"strings"

	"github.com/Yunushan/accessweaver/internal/jsoninput"
)

type Config struct {
	Name      string   `json:"name"`
	Binary    string   `json:"binary"`
	Args      []string `json:"args"`
	Directory string   `json:"directory"`
	LogPath   string   `json:"logPath"`
}

// readConfig bounds and validates the service document before any child is
// constructed. Path containment is checked separately by the native host.
func readConfig(input io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(input, jsoninput.MaxBytes+1))
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := jsoninput.Decode(data, &cfg); err != nil {
		return Config{}, err
	}
	if len(cfg.Args) > 128 {
		return Config{}, errors.New("service configuration argument limit exceeded")
	}
	for _, value := range append([]string{cfg.Name, cfg.Binary, cfg.Directory, cfg.LogPath}, cfg.Args...) {
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return Config{}, errors.New("invalid service configuration value")
		}
	}
	if cfg.Name == "" || cfg.Binary == "" || cfg.Directory == "" || cfg.LogPath == "" {
		return Config{}, errors.New("service configuration is missing a required value")
	}
	return cfg, nil
}
