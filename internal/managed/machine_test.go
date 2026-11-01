package managed

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestInstallationBindsPinnedKeyAndTrustedRevisionFloor(t *testing.T) {
	payload, public, private, now := fixture(t)
	signed, err := Sign(payload, private, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareInstallation(signed, public, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := DecodeInstallation(prepared, now)
	if err != nil {
		t.Fatal(err)
	}
	if authority.verified.Policy.Revision != 2 || authority.verified.RuntimeEnforced {
		t.Fatal("installation parsing claimed unimplemented enforcement")
	}
	var installation Installation
	if err := json.Unmarshal(prepared, &installation); err != nil {
		t.Fatal(err)
	}
	installation.MinimumRevision = 2
	stale, _ := json.Marshal(installation)
	if _, err := DecodeInstallation(stale, now); err == nil {
		t.Fatal("machine revision floor ignored")
	}
	if _, err := DecodeInstallation(prepared, now.Add(2*time.Hour)); err == nil {
		t.Fatal("installed expiry ignored")
	}
	for _, invalid := range [][]byte{bytes.Replace(prepared, []byte(`"minimumRevision": 1,`), nil, 1), bytes.Replace(prepared, []byte(`"minimumRevision": 1`), []byte(`"minimumRevision": null`), 1)} {
		if _, err := DecodeInstallation(invalid, now); err == nil {
			t.Fatal("missing revision floor silently reset to bootstrap")
		}
	}
	duplicate := bytes.Replace(prepared, []byte(`"minimumRevision": 1`), []byte(`"minimumRevision": 1,"minimumRevision":0`), 1)
	if _, err := DecodeInstallation(duplicate, now); err == nil {
		t.Fatal("duplicate trusted revision field accepted")
	}
	if _, err := DecodeInstallation(bytes.Repeat([]byte(" "), MaxInstallationBytes+1), now); err == nil {
		t.Fatal("oversize installation accepted")
	}
	installation.MinimumRevision = 1
	installation.PublicKey = "invalid"
	swapped, _ := json.Marshal(installation)
	if _, err := DecodeInstallation(swapped, now); err == nil {
		t.Fatal("invalid machine trust key accepted")
	}
}

func FuzzDecodeInstallation(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":1,"publicKey":"invalid","minimumRevision":0,"envelope":{"schemaVersion":1,"keyId":"invalid","payload":"","signature":""}}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeInstallation(data, time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC))
	})
}
