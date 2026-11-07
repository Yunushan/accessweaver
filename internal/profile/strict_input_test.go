package profile

import (
	"bytes"
	_ "embed"
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

//go:embed testdata/timestamps.json
var timestampCasesJSON []byte

type timestampCase struct {
	ID       string          `json:"id"`
	Present  bool            `json:"present"`
	Value    json.RawMessage `json:"value"`
	Accepted bool            `json:"accepted"`
}

func profileTimestampCases(tb testing.TB) []timestampCase {
	tb.Helper()
	var table struct {
		SchemaVersion int             `json:"schemaVersion"`
		Cases         []timestampCase `json:"cases"`
	}
	if json.Unmarshal(timestampCasesJSON, &table) != nil || table.SchemaVersion != 1 || len(table.Cases) != 65 {
		tb.Fatal("timestamp conformance table differs")
	}
	seen := make(map[string]bool)
	for _, c := range table.Cases {
		if c.ID == "" || seen[c.ID] || !json.Valid(c.Value) {
			tb.Fatal("invalid timestamp conformance case")
		}
		seen[c.ID] = true
	}
	return table.Cases
}

func timestampProfileJSON(tb testing.TB, c timestampCase) []byte {
	tb.Helper()
	base, err := json.Marshal(New("timestamp-profile", "Timestamp fixture", "byedpi"))
	if err != nil {
		tb.Fatal("timestamp fixture encoding failed")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(base, &fields) != nil {
		tb.Fatal("timestamp fixture fields failed")
	}
	delete(fields, "updatedAt")
	if c.Present {
		fields["updatedAt"] = c.Value
	}
	data, err := json.Marshal(fields)
	if err != nil {
		tb.Fatal("timestamp fixture document failed")
	}
	return data
}

func TestProfileTimestampConformance(t *testing.T) {
	for _, c := range profileTimestampCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			got, err := Decode(bytes.NewReader(timestampProfileJSON(t, c)))
			if (err == nil) != c.Accepted {
				t.Fatal("profile timestamp acceptance differs")
			}
			if err != nil {
				return
			}
			var expected time.Time
			if c.Present && string(c.Value) != "null" {
				var text string
				if json.Unmarshal(c.Value, &text) != nil {
					t.Fatal("accepted timestamp is not text")
				}
				expected, err = time.Parse(time.RFC3339Nano, text)
				if err != nil {
					t.Fatal("accepted timestamp has no calendar meaning")
				}
			}
			if !got.UpdatedAt.Equal(expected) {
				t.Fatal("timestamp instant or null meaning changed")
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal("accepted timestamp cannot be serialized")
			}
			again, err := Decode(bytes.NewReader(encoded))
			if err != nil || !again.UpdatedAt.Equal(expected) {
				t.Fatal("timestamp does not round trip")
			}
		})
	}
}

func FuzzDecodeProfile(f *testing.F) {
	seed, _ := json.Marshal(New("fuzz-profile", "Profile", "byedpi"))
	f.Add(seed)
	for _, c := range profileTimestampCases(f) {
		f.Add(timestampProfileJSON(f, c))
	}
	dated := New("fuzz-profile", "Profile", "byedpi")
	dated.UpdatedAt = time.Date(2026, 11, 7, 12, 34, 56, 0, time.UTC)
	datedSeed, _ := json.Marshal(dated)
	f.Add(bytes.Replace(datedSeed, []byte("2026-11-07T12:34:56Z"), []byte("2026-11-07T12:34:56+00:00"), 1))
	f.Add(bytes.Replace(datedSeed, []byte("2026-11-07T12:34:56Z"), []byte("2026-11-07T12:34:56+24:00"), 1))
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
