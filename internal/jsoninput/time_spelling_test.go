package jsoninput

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This temporary characterization records the existing typed-time mismatch.
// Replace the rejection expectation with acceptance after native confirmation.
func TestTimestampRawJSONSpellingCharacterization(t *testing.T) {
	const canonical = "2026-11-07T12:34:56.123456789+03:00"
	quoted, _ := json.Marshal(canonical)
	spellings := []struct {
		id      string
		value   string
		escaped bool
	}{
		{"literal", string(quoted), false},
		{"year", strings.Replace(string(quoted), "2", `\u0032`, 1), true},
		{"separator", strings.Replace(string(quoted), "T", `\u0054`, 1), true},
		{"colon", strings.ReplaceAll(string(quoted), ":", `\u003a`), true},
		{"hyphen", strings.ReplaceAll(string(quoted), "-", `\u002d`), true},
		{"fraction", strings.Replace(string(quoted), ".", `\u002e`, 1), true},
		{"offset", strings.Replace(string(quoted), "+", `\u002b`, 1), true},
	}
	expected, err := time.Parse(time.RFC3339Nano, canonical)
	if err != nil {
		t.Fatal("timestamp fixture is invalid")
	}
	for _, c := range spellings {
		t.Run(c.id, func(t *testing.T) {
			body := []byte(`{"at":` + c.value + `}`)
			before := bytes.Clone(body)
			var plain struct {
				At string `json:"at"`
			}
			if Decode(body, &plain) != nil || plain.At != canonical || !ValidTimestamp(plain.At) {
				t.Fatal("equivalent timestamp spelling changed decoded string meaning")
			}
			original := struct {
				At time.Time `json:"at"`
			}{At: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
			got := original
			err := Decode(body, &got)
			if c.escaped {
				var parseError *time.ParseError
				if !errors.Is(err, ErrInvalid) || !errors.As(err, &parseError) || !reflect.DeepEqual(got, original) {
					t.Fatal("typed timestamp spelling mismatch characterization differs")
				}
				var sdk struct {
					At time.Time `json:"at"`
				}
				if json.Unmarshal(body, &sdk) == nil {
					t.Fatal("SDK timestamp unexpectedly accepted escaped spelling")
				}
			} else if err != nil || !got.At.Equal(expected) {
				t.Fatal("literal timestamp control did not decode")
			}
			if !bytes.Equal(body, before) {
				t.Fatal("timestamp decode changed source bytes")
			}
		})
	}
}
