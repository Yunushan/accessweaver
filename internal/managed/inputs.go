package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// LaunchDigest excludes display metadata and diagnostic probes. Binary/config
// content require their separate trusted digests; this binds launch inputs only.
func LaunchDigest(p LaunchInput) (string, error) {
	input := struct {
		Version    int          `json:"version"`
		Engine     string       `json:"engine"`
		Binary     string       `json:"binary"`
		ConfigPath string       `json:"configPath"`
		SHA256     string       `json:"sha256"`
		Args       []string     `json:"args"`
		Routing    RoutingInput `json:"routing"`
	}{p.Version, p.Engine, p.Binary, p.ConfigPath, strings.ToLower(p.SHA256), append([]string{}, p.Args...), RoutingInput{
		IncludeDomains: append([]string{}, p.Routing.IncludeDomains...), ExcludeDomains: append([]string{}, p.Routing.ExcludeDomains...), Applications: append([]string{}, p.Routing.Applications...),
	}}
	return InputDigest("launch", input)
}

// InputDigest binds the typed JSON representation and its versioned purpose.
// Callers must validate their input before hashing; hashing grants no authority.
func InputDigest(kind string, input any) (string, error) {
	if kind != "launch" && kind != "workflow" {
		return "", errors.New("unknown managed input digest purpose")
	}
	data, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("AccessWeaver managed "+kind+" input v1\x00"), data...))
	return hex.EncodeToString(sum[:]), nil
}

// LaunchInput is separate from profile persistence so policy can also protect
// the store without creating an import cycle. Callers validate the profile first.
type LaunchInput struct {
	Version    int
	Engine     string
	Binary     string
	ConfigPath string
	SHA256     string
	Args       []string
	Routing    RoutingInput
}

type RoutingInput struct {
	IncludeDomains []string `json:"includeDomains"`
	ExcludeDomains []string `json:"excludeDomains"`
	Applications   []string `json:"applications"`
}
