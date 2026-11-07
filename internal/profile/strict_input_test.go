package profile

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProfileDecodeRejectsAmbiguousFields(t *testing.T) {
	profile := New("canonical-profile", "Original", "byedpi")
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	source := string(encoded)
	for _, input := range []string{
		strings.Replace(source, `"id":`, `"id":"canonical-profile","id":`, 1),
		strings.Replace(source, `"id":`, `"ID":`, 1),
		strings.Replace(source, `"name":`, `"\u006eame":"Original","name":`, 1),
		strings.Replace(source, `"includeDomains":`, `"IncludeDomains":`, 1),
		strings.Replace(source, `"tls":`, `"tls":false,"tls":`, 1),
		strings.Replace(source, `"tls":true`, `"tls":null`, 1),
		strings.Replace(source, `"name":"Original"`, `"name":"`+string([]byte{0xff})+`"`, 1),
	} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatal("ambiguous profile was accepted")
		}
	}
	got, err := Decode(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(got, profile) {
		t.Fatal("canonical profile failed to retain its fields")
	}
}

func FuzzDecodeProfile(f *testing.F) {
	seed, _ := json.Marshal(New("fuzz-profile", "Profile", "byedpi"))
	f.Add(seed)
	dated := New("fuzz-profile", "Profile", "byedpi")
	dated.UpdatedAt = time.Date(2026, 11, 7, 12, 34, 56, 0, time.UTC)
	datedSeed, _ := json.Marshal(dated)
	f.Add(bytes.Replace(datedSeed, []byte("2026-11-07T12:34:56Z"), []byte("2026-11-07T12:34:56+00:00"), 1))
	f.Add([]byte(`{}`))
	f.Add(append(bytes.Clone(seed), []byte(` {}`)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		if got.Validate() != nil {
			t.Fatal("decoder returned an invalid profile")
		}
		encoded, err := json.Marshal(got)
		roundtrip, again := Decode(bytes.NewReader(encoded))
		if err != nil || again != nil || !got.UpdatedAt.Equal(roundtrip.UpdatedAt) {
			t.Fatal("accepted profile did not retain its timestamp")
		}
		got.UpdatedAt, roundtrip.UpdatedAt = time.Time{}, time.Time{}
		if !reflect.DeepEqual(got, roundtrip) {
			t.Fatal("accepted profile did not round trip")
		}
		id, _ := json.Marshal(got.ID)
		duplicate := append(append([]byte(`{"id":`), id...), ',')
		duplicate = append(duplicate, bytes.TrimSpace(data)[1:]...)
		if _, err := Decode(bytes.NewReader(duplicate)); err == nil {
			t.Fatal("duplicate profile identity accepted")
		}
	})
}
