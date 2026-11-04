// Package managed defines signed administrator policy documents. Verification
// alone does not enroll a machine or enforce policy in runtime execution paths.
package managed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const MaxPolicyBytes = 64 << 10
const MaxEnvelopeBytes = 128 << 10
const signatureDomain = "AccessWeaver managed policy v1\x00"

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var enginePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,49}$`)

// Empty allowlists and false permissions are deny-by-default policy intent.
// Execution guards and a protected machine trust store must consume this intent.
type Policy struct {
	Downloads           []DownloadRule `json:"downloads,omitempty"`
	SchemaVersion       int            `json:"schemaVersion"`
	Revision            uint64         `json:"revision"`
	IssuedAt            time.Time      `json:"issuedAt"`
	ExpiresAt           time.Time      `json:"expiresAt"`
	AllowDownloads      bool           `json:"allowDownloads"`
	AllowDiagnostics    bool           `json:"allowDiagnostics"`
	AllowProfileChanges bool           `json:"allowProfileChanges"`
	RequireProfileAudit bool           `json:"requireProfileAudit,omitempty"`
	Launches            []LaunchRule   `json:"launches"`
	Workflows           []WorkflowRule `json:"workflows"`
}

type DownloadRule struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type LaunchRule struct {
	Engine       string `json:"engine"`
	InputSHA256  string `json:"inputSHA256"`
	BinarySHA256 string `json:"binarySHA256"`
	ConfigSHA256 string `json:"configSHA256,omitempty"`
}

type WorkflowRule struct {
	Action      string `json:"action"`
	InputSHA256 string `json:"inputSHA256"`
}

type Envelope struct {
	SchemaVersion int    `json:"schemaVersion"`
	KeyID         string `json:"keyId"`
	Payload       string `json:"payload"`
	Signature     string `json:"signature"`
}

type Verified struct {
	Policy          Policy `json:"policy"`
	KeyID           string `json:"keyId"`
	PayloadSHA256   string `json:"payloadSHA256"`
	SignatureValid  bool   `json:"signatureValid"`
	RuntimeEnforced bool   `json:"runtimeEnforced"`
}

func KeyID(key ed25519.PublicKey) string {
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:])
}

func PublicKey(encoded string) (ed25519.PublicKey, error) {
	b, err := canonicalBase64(encoded, ed25519.PublicKeySize, ed25519.PublicKeySize)
	if err != nil {
		return nil, errors.New("expected a canonical base64 Ed25519 public key (32 bytes)")
	}
	key := ed25519.PublicKey(b)
	if err := validatePublicKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func DecodePolicy(data []byte, now time.Time, minimumRevision uint64) (Policy, error) {
	var p Policy
	if err := strictJSON(data, MaxPolicyBytes, &p); err != nil {
		return p, err
	}
	if p.SchemaVersion != 1 {
		return p, errors.New("unsupported managed policy schema version")
	}
	// Keep revisions exact in JSON consumers that use IEEE-754 numbers.
	if p.Revision == 0 || p.Revision > (1<<53)-1 || p.Revision <= minimumRevision {
		return p, errors.New("policy revision must be a positive safe integer newer than the minimum revision")
	}
	if now.IsZero() || p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) {
		return p, errors.New("policy requires valid issuedAt and expiresAt timestamps")
	}
	if p.IssuedAt.After(now.Add(5 * time.Minute)) {
		return p, errors.New("policy issuance is in the future")
	}
	if !p.ExpiresAt.After(now) {
		return p, errors.New("policy has expired")
	}
	if len(p.Launches) > 128 || len(p.Workflows) > 128 || len(p.Downloads) > 128 {
		return p, errors.New("policy allowlist exceeds 128 entries")
	}
	urls := map[string]bool{}
	for _, download := range p.Downloads {
		parsed, err := url.Parse(download.URL)
		if err != nil || len(download.URL) > 4096 || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || !digestPattern.MatchString(download.SHA256) {
			return p, errors.New("invalid pinned download URL or SHA-256")
		}
		if urls[download.URL] {
			return p, errors.New("duplicate pinned download URL")
		}
		urls[download.URL] = true
	}
	seen := map[string]bool{}
	for _, rule := range p.Launches {
		if !enginePattern.MatchString(rule.Engine) || !digestPattern.MatchString(rule.InputSHA256) || !digestPattern.MatchString(rule.BinarySHA256) || rule.ConfigSHA256 != "" && !digestPattern.MatchString(rule.ConfigSHA256) {
			return p, errors.New("invalid launch rule: require an engine and lowercase SHA-256 digests")
		}
		id := rule.Engine + ":" + rule.InputSHA256
		if seen[id] {
			return p, errors.New("duplicate launch rule")
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, rule := range p.Workflows {
		if !enginePattern.MatchString(rule.Action) || !digestPattern.MatchString(rule.InputSHA256) {
			return p, errors.New("invalid workflow rule")
		}
		id := rule.Action + ":" + rule.InputSHA256
		if seen[id] {
			return p, errors.New("duplicate workflow rule")
		}
		seen[id] = true
	}
	return p, nil
}

// Sign binds the exact payload bytes, including whitespace, to a domain-separated
// Ed25519 signature. Private signing keys never belong in the deployed envelope.
func Sign(payload []byte, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) {
		return nil, errors.New("inconsistent Ed25519 private key")
	}
	if _, err := DecodePolicy(payload, now, 0); err != nil {
		return nil, err
	}
	public := key.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(key, append([]byte(signatureDomain), payload...))
	envelope := Envelope{1, KeyID(public), base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(signature)}
	result, err := json.MarshalIndent(envelope, "", "  ")
	return append(result, '\n'), err
}

// Verify uses only the caller's pinned public key, never a key supplied by the
// envelope. minimumRevision must come from trusted state to prevent rollback.
func Verify(data []byte, public ed25519.PublicKey, now time.Time, minimumRevision uint64) (Verified, error) {
	var result Verified
	if err := validatePublicKey(public); err != nil {
		return result, err
	}
	var envelope Envelope
	if err := strictJSON(data, MaxEnvelopeBytes, &envelope); err != nil {
		return result, err
	}
	if envelope.SchemaVersion != 1 {
		return result, errors.New("unsupported managed envelope schema version")
	}
	if envelope.KeyID != KeyID(public) {
		return result, errors.New("envelope key ID does not match the pinned public key")
	}
	payload, err := canonicalBase64(envelope.Payload, 1, MaxPolicyBytes)
	if err != nil {
		return result, errors.New("invalid policy payload encoding or size")
	}
	signature, err := canonicalBase64(envelope.Signature, ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil {
		return result, errors.New("invalid policy signature encoding")
	}
	if !ed25519.Verify(public, append([]byte(signatureDomain), payload...), signature) {
		return result, errors.New("policy signature verification failed")
	}
	policy, err := DecodePolicy(payload, now, minimumRevision)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(payload)
	return Verified{policy, envelope.KeyID, hex.EncodeToString(digest[:]), true, false}, nil
}

func canonicalBase64(value string, min, max int) ([]byte, error) {
	if len(value) > base64.StdEncoding.EncodedLen(max) {
		return nil, errors.New("base64 exceeds limit")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < min || len(decoded) > max || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid canonical base64")
	}
	return decoded, nil
}

// Reject duplicate keys (also nested), trailing values, unknown fields, excess
// nesting and oversize data before decoding a security-relevant document.
func strictJSON(data []byte, limit int, target any) error {
	if len(data) > limit {
		return errors.New("managed document exceeds size limit")
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	tokens.UseNumber()
	var value func(int, reflect.Type) error
	value = func(depth int, shape reflect.Type) error {
		if depth > 16 {
			return errors.New("managed JSON nesting exceeds limit")
		}
		token, err := tokens.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			if shape.Kind() == reflect.Bool {
				if _, ok := token.(bool); !ok {
					return errors.New("managed boolean fields require true or false")
				}
			}
			return nil
		}
		switch delimiter {
		case '{':
			if shape.Kind() != reflect.Struct {
				return errors.New("JSON object does not match managed schema")
			}
			fields := map[string]reflect.Type{}
			for i := 0; i < shape.NumField(); i++ {
				field := shape.Field(i)
				if field.PkgPath != "" {
					continue
				}
				name := strings.Split(field.Tag.Get("json"), ",")[0]
				if name != "" && name != "-" {
					fields[name] = field.Type
				}
			}
			keys := map[string]bool{}
			for tokens.More() {
				token, err := tokens.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok {
					return errors.New("expected JSON object key")
				}
				if keys[key] {
					return errors.New("duplicate managed JSON field")
				}
				keys[key] = true
				field, ok := fields[key]
				if !ok {
					return errors.New("unknown or noncanonical managed JSON field")
				}
				if err := value(depth+1, field); err != nil {
					return err
				}
			}
		case '[':
			if shape.Kind() != reflect.Slice && shape.Kind() != reflect.Array {
				return errors.New("JSON array does not match managed schema")
			}
			for tokens.More() {
				if err := value(depth+1, shape.Elem()); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = tokens.Token()
		return err
	}
	if err := value(0, reflect.TypeOf(target).Elem()); err != nil {
		return fmt.Errorf("invalid managed JSON: %w", err)
	}
	if _, err := tokens.Token(); err != io.EOF {
		return errors.New("expected one managed JSON document")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid managed document: %w", err)
	}
	return nil
}
