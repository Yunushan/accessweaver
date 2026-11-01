package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Yunushan/accessweaver/internal/profile"
)

// LaunchDigest excludes display metadata and diagnostic probes. Binary/config
// content require their separate trusted digests; this binds launch inputs only.
func LaunchDigest(p profile.Profile) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	input := struct {
		Version    int             `json:"version"`
		Engine     string          `json:"engine"`
		Binary     string          `json:"binary"`
		ConfigPath string          `json:"configPath"`
		SHA256     string          `json:"sha256"`
		Args       []string        `json:"args"`
		Routing    profile.Routing `json:"routing"`
	}{p.Version, p.Engine, p.Binary, p.ConfigPath, strings.ToLower(p.SHA256), append([]string{}, p.Args...), profile.Routing{
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
