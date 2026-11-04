package audit

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
)

func fixtureActorKey() (key [32]byte) {
	for i := range key {
		key[i] = byte(i)
	}
	return key
}
func TestProcessProducerIndependentPseudonymVectorAndScope(t *testing.T) {
	key := fixtureActorKey()
	principal := processPrincipal{"uid", "1000", "user"}
	info := buildinfo.Info{Commit: strings.Repeat("b", 40), SourceState: "clean", Platform: "linux", Arch: "amd64"}
	producer, err := producerForProcess(key, principal, info)
	// Independently computed with Python hmac/hashlib, explicit NUL-separated
	// byte strings and key bytes 00..1f. No live principal or enrollment key.
	if err != nil || producer.ActorSHA256 != "6b3b544e27dc61c7a86ceac6517162669292d0f2279061ba9f1b59f690fdb512" || producer.SourceCommit != info.Commit || producer.SourceState != info.SourceState || producer.Target != "linux/amd64" || producer.ActorClass != "user" {
		t.Fatalf("vector differs: %+v %v", producer, err)
	}
	changedKey := key
	changedKey[0]++
	other, err := producerForProcess(changedKey, principal, info)
	if err != nil || other.ActorSHA256 == producer.ActorSHA256 {
		t.Fatal("key rotation did not change pseudonym", err)
	}
	otherPrincipal := principal
	otherPrincipal.value = "1001"
	other, err = producerForProcess(key, otherPrincipal, info)
	if err != nil || other.ActorSHA256 == producer.ActorSHA256 {
		t.Fatal("different principal conflated", err)
	}
	otherInfo := info
	otherInfo.Platform = "darwin"
	other, err = producerForProcess(key, principal, otherInfo)
	if err != nil || other.ActorSHA256 == producer.ActorSHA256 {
		t.Fatal("OS namespace conflated", err)
	}
	// Architecture/source/elevation belong to the full producer binding, while
	// the pseudonym identifies the principal within its keyed OS namespace.
	for _, target := range []string{"windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "freebsd/amd64", "freebsd/arm64", "openbsd/amd64", "openbsd/arm64"} {
		parts := strings.Split(target, "/")
		candidate := info
		candidate.Platform, candidate.Arch = parts[0], parts[1]
		identity := principal
		if parts[0] == "windows" {
			identity.kind, identity.value = "sid", "S-1-5-21-123-456-789-1000"
		}
		p, err := producerForProcess(key, identity, candidate)
		if err != nil || !validProducer(p) || p.Target != target {
			t.Fatal("documented target lost", target, err)
		}
	}
}
func TestProcessProducerRefusesUnavailableOrMalformedMetadataWithoutIdentityLeak(t *testing.T) {
	key := fixtureActorKey()
	principal := processPrincipal{"uid", "private-principal-that-must-not-appear", "user"}
	info := buildinfo.Info{Commit: "unknown", SourceState: "unknown", Platform: "linux", Arch: "amd64"}
	for _, test := range []struct {
		key       [32]byte
		principal processPrincipal
		info      buildinfo.Info
	}{
		{[32]byte{}, principal, info},
		{key, processPrincipal{"environment", principal.value, "user"}, info},
		{key, processPrincipal{"uid", principal.value, "administrator-from-environment"}, info},
		{key, processPrincipal{"uid", "", "user"}, info},
		{key, processPrincipal{"uid", "private\x00principal", "user"}, info},
		{key, processPrincipal{"uid", strings.Repeat("p", 257), "user"}, info},
		{key, principal, buildinfo.Info{Commit: "private-invalid-source", SourceState: "clean", Platform: "linux", Arch: "amd64"}},
		{key, principal, buildinfo.Info{Commit: "unknown", SourceState: "clean", Platform: "linux", Arch: "amd64"}},
		{key, principal, buildinfo.Info{Commit: "unknown", SourceState: "unknown", Platform: "linux", Arch: "386"}},
		{key, principal, buildinfo.Info{Commit: "unknown", SourceState: "unknown", Platform: "unsupported", Arch: "amd64"}},
	} {
		got, err := producerForProcess(test.key, test.principal, test.info)
		if !errors.Is(err, ErrProcessIdentity) || got != (Producer{}) || err.Error() != ErrProcessIdentity.Error() {
			t.Fatalf("private metadata or partial producer escaped: %+v %v", got, err)
		}
	}
	if got, err := ProcessProducer([32]byte{}); !errors.Is(err, ErrProcessIdentity) || got != (Producer{}) {
		t.Fatal("zero key admitted", err)
	}
}
func TestProcessProducerReadsNativeCredentialsAndIgnoresIdentityEnvironment(t *testing.T) {
	switch runtime.GOOS {
	case "windows", "linux", "darwin", "freebsd", "openbsd":
	default:
		t.Skip("unsupported native principal")
	}
	key := fixtureActorKey()
	before, err := ProcessProducer(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"USER", "USERNAME", "LOGNAME", "SUDO_USER", "SUDO_UID", "SUDO_GID", "DOMAIN", "USERDOMAIN"} {
		t.Setenv(name, "private-spoofed-audit-principal")
	}
	after, err := ProcessProducer(key)
	if err != nil || before != after || !validProducer(after) || after.Target != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("OS identity changed with environment: %v", err)
	}
	info := buildinfo.Current()
	if after.SourceCommit != info.Commit || after.SourceState != info.SourceState {
		t.Fatal("running source metadata lost")
	}
	wire, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "private-spoofed") || strings.Contains(string(wire), "S-1-") {
		t.Fatal("raw principal in wire metadata")
	}
	start, err := NewStream(after)
	if err != nil {
		t.Fatal(err)
	}
	line, end, err := Append(start, fixtureEvent(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFixture(line, start, end); err != nil {
		t.Fatal("derived producer did not bind valid stream", err)
	}
}
