package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Yunushan/accessweaver/internal/jsoninput"
)

const SchemaVersion = 1

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
var domainPattern = regexp.MustCompile(`^(\^)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var hashPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

type Profile struct {
	Version     int       `json:"version"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Category    string    `json:"category,omitempty"`
	Engine      string    `json:"engine"`
	Binary      string    `json:"binary,omitempty"`
	ConfigPath  string    `json:"configPath,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	Args        []string  `json:"args"`
	Routing     Routing   `json:"routing"`
	Probe       Probe     `json:"probe"`
	Notes       string    `json:"notes,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt,omitempty"`
}

type Routing struct {
	IncludeDomains []string `json:"includeDomains"`
	ExcludeDomains []string `json:"excludeDomains"`
	Applications   []string `json:"applications"`
}

type Probe struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	TLS            bool   `json:"tls"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

func New(id, name, engine string) Profile {
	return Profile{Version: SchemaVersion, ID: id, Name: name, Engine: engine,
		Args: []string{}, Routing: Routing{IncludeDomains: []string{}, ExcludeDomains: []string{}, Applications: []string{}},
		Probe: Probe{Host: "discord.com", Port: 443, TLS: true, TimeoutSeconds: 5}}
}

func Decode(r io.Reader) (Profile, error) {
	var p Profile
	// Read one extra byte so trailing whitespace cannot hide an oversized file.
	data, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return p, err
	}
	if len(data) > 1<<20 {
		return p, errors.New("profile exceeds 1 MiB")
	}
	if err := jsoninput.Decode(data, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}

func (p Profile) Validate() error {
	if p.Version != SchemaVersion {
		return fmt.Errorf("unsupported profile version %d (expected %d)", p.Version, SchemaVersion)
	}
	if !idPattern.MatchString(p.ID) {
		return fmt.Errorf("invalid id %q: use 2–63 lowercase letters, digits, hyphens", p.ID)
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 100 {
		return errors.New("name must have 1–100 characters")
	}
	if len(p.Description) > 4000 || len(p.Notes) > 10000 {
		return errors.New("description or notes too long")
	}
	if len(p.Engine) == 0 || len(p.Engine) > 50 {
		return errors.New("engine is required")
	}
	if len(p.Binary) > 2048 || len(p.ConfigPath) > 4096 || strings.ContainsAny(p.Binary+p.ConfigPath, "\x00\r\n") {
		return errors.New("binary or configuration path is too long or contains control characters")
	}
	if p.SHA256 != "" && !hashPattern.MatchString(p.SHA256) {
		return errors.New("sha256 must be a 64-digit hexadecimal string")
	}
	if len(p.Args) > 128 {
		return errors.New("too many arguments (128 maximum)")
	}
	for _, s := range p.Args {
		if len(s) > 4096 || strings.ContainsRune(s, 0) {
			return errors.New("argument too long or contains NUL")
		}
	}
	if p.Probe.Host != "" {
		if err := ValidateHost(p.Probe.Host); err != nil {
			return fmt.Errorf("probe host: %w", err)
		}
	}
	if p.Probe.Port < 1 || p.Probe.Port > 65535 {
		return errors.New("probe port out of range")
	}
	if p.Probe.TimeoutSeconds < 1 || p.Probe.TimeoutSeconds > 60 {
		return errors.New("probe timeout must be 1–60 seconds")
	}
	if err := validateDomains("includeDomains", p.Routing.IncludeDomains); err != nil {
		return err
	}
	if err := validateDomains("excludeDomains", p.Routing.ExcludeDomains); err != nil {
		return err
	}
	if len(p.Routing.Applications) > 100 {
		return errors.New("too many applications")
	}
	for _, s := range p.Routing.Applications {
		if strings.TrimSpace(s) == "" || len(s) > 2048 || strings.ContainsRune(s, 0) {
			return errors.New("invalid application path")
		}
	}
	included := make(map[string]bool, len(p.Routing.IncludeDomains))
	for _, in := range p.Routing.IncludeDomains {
		included[strings.ToLower(in)] = true
	}
	for _, out := range p.Routing.ExcludeDomains {
		if included[strings.ToLower(out)] {
			return fmt.Errorf("domain %q is both included and excluded", out)
		}
	}
	return nil
}

// ValidateHost deliberately excludes engine-only hostlist syntax such as ^.
func ValidateHost(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	if strings.HasPrefix(host, "^") {
		return errors.New("exact-match prefixes are only valid in domain rules")
	}
	return ValidateDomain(host)
}

func ValidateDomain(d string) error {
	if len(d) < 1 || len(d) > 253 || strings.ContainsAny(d, " \t\n\r\x00/:\\") || !domainPattern.MatchString(strings.ToLower(d)) {
		return fmt.Errorf("invalid domain %q (use ASCII/IDNA DNS names, optional ^ for exact match)", d)
	}
	return nil
}
func validateDomains(field string, values []string) error {
	if len(values) > 4096 {
		return fmt.Errorf("%s exceeds 4096 domains", field)
	}
	seen := map[string]bool{}
	for _, value := range values {
		if err := ValidateDomain(value); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		lower := strings.ToLower(value)
		if seen[lower] {
			return fmt.Errorf("%s: duplicate %q", field, value)
		}
		seen[lower] = true
	}
	return nil
}

func (p Profile) Copy() Profile {
	b, _ := json.Marshal(p)
	var out Profile
	_ = json.Unmarshal(b, &out)
	return out
}
