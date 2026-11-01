package backup

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/Yunushan/accessweaver/internal/profile"
	"reflect"
	"testing"
	"time"
)

const testPassword = "a long private test passphrase"

func TestArchiveRoundTripAuthenticationAndRandomness(t *testing.T) {
	profiles := []profile.Profile{profile.New("backup-test", "PRIVATE_PROFILE_NAME", "byedpi")}
	profiles[0].Args = []string{"PRIVATE_INLINE_SECRET"}
	when := time.Now().UTC().Truncate(time.Second)
	data, err := Encrypt(profiles, testPassword, when)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"PRIVATE_PROFILE_NAME", "PRIVATE_INLINE_SECRET", testPassword} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatal("plaintext entered archive")
		}
	}
	got, err := Decrypt(data, testPassword)
	if err != nil || !reflect.DeepEqual(got.Profiles, profiles) || !got.CreatedAt.Equal(when) {
		t.Fatal(got, err)
	}
	second, err := Encrypt(profiles, testPassword, when)
	if err != nil || bytes.Equal(data, second) {
		t.Fatal("encryption reused salt/nonce", err)
	}
	if _, err := Decrypt(data, "a different wrong passphrase"); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	for _, offset := range []int{16, 32, HeaderBytes, len(data) - 1} {
		corrupted := bytes.Clone(data)
		corrupted[offset] ^= 1
		if _, err := Decrypt(corrupted, testPassword); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("tampering at %d accepted: %v", offset, err)
		}
	}
}
func TestArchiveRejectsParametersLimitsAndInvalidProfiles(t *testing.T) {
	profiles := []profile.Profile{profile.New("backup-test", "Test", "byedpi")}
	data, err := Encrypt(profiles, testPassword, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 8, 9, 10, 11, 12, 15} {
		changed := bytes.Clone(data)
		changed[offset] ^= 1
		if _, err := Decrypt(changed, testPassword); err == nil || errors.Is(err, ErrAuthentication) {
			t.Fatalf("header not rejected before KDF at %d: %v", offset, err)
		}
	}
	changed := bytes.Clone(data)
	binary.BigEndian.PutUint32(changed[12:16], 0xffffffff)
	if _, err := Decrypt(changed, testPassword); err == nil {
		t.Fatal("unbounded work factor accepted")
	}
	for _, invalid := range [][]byte{nil, data[:HeaderBytes], make([]byte, MaxArchiveBytes+1)} {
		if _, err := Decrypt(invalid, testPassword); err == nil {
			t.Fatal("invalid size accepted")
		}
	}
	for _, password := range []string{"short", string([]byte{255})} {
		if _, err := Encrypt(profiles, password, time.Now()); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
	if _, err := Encrypt(append(profiles, profiles[0]), testPassword, time.Now()); err == nil {
		t.Fatal("duplicate profiles accepted")
	}
	if _, err := Encrypt(profiles, testPassword, time.Time{}); err == nil {
		t.Fatal("missing timestamp accepted")
	}
}
func TestStrictSnapshotRejectsAmbiguousJSON(t *testing.T) {
	for _, data := range []string{
		`{"schemaVersion":1,"schemaVersion":1}`,
		`{"SchemaVersion":1}`,
		`{"schemaVersion":1,"profiles":[{"ID":"alias"}]}`,
		`{"profiles":[{"id":"aa","id":"bb"}]}`,
		`{"profiles":{}}`,
		`{} {}`,
	} {
		if strictSnapshot([]byte(data)) == nil {
			t.Fatal("ambiguous snapshot accepted", data)
		}
	}
}
