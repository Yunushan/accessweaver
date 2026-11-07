package jsoninput

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The application must accept equivalent valid JSON string spellings.
// Fixed observations keep the direct SDK method distinct from the actual codec.
// No input bytes, timestamps, paths or native error text enter the report.
func TestTimestampRawJSONSpellingAcceptance(t *testing.T) {
	const canonical = "2026-11-07T12:34:56.123456789+03:00"
	quoted, _ := json.Marshal(canonical)
	spellings := []struct {
		id    string
		value string
	}{
		{"literal", string(quoted)},
		{"year", strings.Replace(string(quoted), "2", `\u0032`, 1)},
		{"separator", strings.Replace(string(quoted), "T", `\u0054`, 1)},
		{"colon", strings.ReplaceAll(string(quoted), ":", `\u003a`)},
		{"hyphen", strings.ReplaceAll(string(quoted), "-", `\u002d`)},
		{"fraction", strings.Replace(string(quoted), ".", `\u002e`, 1)},
		{"offset", strings.Replace(string(quoted), "+", `\u002b`, 1)},
	}
	expected, err := time.Parse(time.RFC3339Nano, canonical)
	if err != nil {
		t.Fatal("timestamp fixture is invalid")
	}
	type observation struct {
		ID                          string `json:"id"`
		StringAccepted              bool   `json:"stringAccepted"`
		StringEqual                 bool   `json:"stringEqual"`
		TimestampValid              bool   `json:"timestampValid"`
		DirectTimeEqual             bool   `json:"directTimeEqual"`
		DirectSDKAccepted           bool   `json:"directSDKAccepted"`
		Equivalent                  bool   `json:"equivalent"`
		ApplicationAccepted         bool   `json:"applicationAccepted"`
		ApplicationTimeEqual        bool   `json:"applicationTimeEqual"`
		ApplicationUnchangedOnError bool   `json:"applicationUnchangedOnError"`
		SDKAccepted                 bool   `json:"sdkAccepted"`
		SDKTimeEqual                bool   `json:"sdkTimeEqual"`
		SourceUnchanged             bool   `json:"sourceUnchanged"`
		Cause                       string `json:"cause"`
	}
	observations := make([]observation, 0, len(spellings))
	for _, c := range spellings {
		body := []byte(`{"at":` + c.value + `}`)
		before := bytes.Clone(body)
		var plain struct {
			At string `json:"at"`
		}
		plainErr := Decode(body, &plain)
		original := struct {
			At time.Time `json:"at"`
		}{At: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
		got := original
		appErr := Decode(body, &got)
		var sdk struct {
			At time.Time `json:"at"`
		}
		sdkErr := json.Unmarshal(body, &sdk)
		var direct time.Time
		directErr := direct.UnmarshalJSON([]byte(c.value))
		cause := "none"
		if appErr != nil {
			cause = "other"
			if errors.Is(appErr, ErrInvalid) {
				cause = "invalid-other"
				var parseError *time.ParseError
				if errors.As(appErr, &parseError) {
					cause = "invalid-parse"
				}
			}
		}
		row := observation{ID: c.id, StringAccepted: plainErr == nil, StringEqual: plain.At == canonical, TimestampValid: ValidTimestamp(plain.At), DirectSDKAccepted: directErr == nil, DirectTimeEqual: directErr == nil && direct.Equal(expected), Equivalent: plainErr == nil && plain.At == canonical && ValidTimestamp(plain.At), ApplicationAccepted: appErr == nil, ApplicationTimeEqual: appErr == nil && got.At.Equal(expected), ApplicationUnchangedOnError: appErr == nil || reflect.DeepEqual(got, original), SDKAccepted: sdkErr == nil, SDKTimeEqual: sdkErr == nil && sdk.At.Equal(expected), SourceUnchanged: bytes.Equal(body, before), Cause: cause}
		observations = append(observations, row)
		if !row.ApplicationAccepted || !row.ApplicationTimeEqual || !row.Equivalent || !row.SourceUnchanged || !row.ApplicationUnchangedOnError || row.ApplicationAccepted && !row.ApplicationTimeEqual || row.SDKAccepted && !row.SDKTimeEqual || row.DirectSDKAccepted && !row.DirectTimeEqual {
			t.Error("timestamp observation invariant differs")
		}
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("ACCESSWEAVER_TIMESTAMP_OBSERVATION") == "1" {
		encoded, err := json.Marshal(observations)
		if err != nil {
			t.Fatal("timestamp observation encoding failed")
		}
		fmt.Printf("ACCESSWEAVER_TIMESTAMP_JSON:%s\n", encoded)
	}
}

// Opaque payloads must retain exact signature-covered bytes while typed timestamp
// fields use the standard codec across pointer, slice and map containers.
func TestTimestampSpellingPreservesOpaquePayload(t *testing.T) {
	const canonical = "2026-11-07T12:34:56.123456789+03:00"
	const spelled = `"\u0032026-11-07T12\u003a34\u003a56.123456789\u002b03\u003a00"`
	payload := []byte(`{ "date" : ` + spelled + `, "counter" : 1e+03 }`)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signature := ed25519.Sign(private, payload)
	body := []byte(`{"at":` + spelled + `,"pointer":` + spelled + `,"list":[` + spelled + `,null],"lookup":{"fixture":` + spelled + `},"payload":` + string(payload) + `}`)
	before := bytes.Clone(body)
	var got struct {
		At      time.Time            `json:"at"`
		Pointer *time.Time           `json:"pointer"`
		List    []time.Time          `json:"list"`
		Lookup  map[string]time.Time `json:"lookup"`
		Payload json.RawMessage      `json:"payload"`
	}
	expected, err := time.Parse(time.RFC3339Nano, canonical)
	if err != nil {
		t.Fatal("timestamp fixture is invalid")
	}
	if Decode(body, &got) != nil || !got.At.Equal(expected) || got.Pointer == nil || !got.Pointer.Equal(expected) || len(got.List) != 2 || !got.List[0].Equal(expected) || !got.List[1].IsZero() || len(got.Lookup) != 1 || !got.Lookup["fixture"].Equal(expected) {
		t.Fatal("equivalent timestamp containers changed meaning")
	}
	if !bytes.Equal(got.Payload, payload) || !ed25519.Verify(private.Public().(ed25519.PublicKey), got.Payload, signature) || !bytes.Equal(body, before) {
		t.Fatal("timestamp decoding changed source or signature-covered payload bytes")
	}
}
