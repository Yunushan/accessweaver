package jsoninput

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Fixed synthetic observations distinguish an SDK mismatch from a bad hypothesis.
// No input bytes, timestamps, paths or native error text enter the report.
func TestTimestampRawJSONSpellingCharacterization(t *testing.T) {
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
		if !row.Equivalent || !row.SourceUnchanged || !row.ApplicationUnchangedOnError || row.ApplicationAccepted && !row.ApplicationTimeEqual || row.SDKAccepted && !row.SDKTimeEqual || row.DirectSDKAccepted && !row.DirectTimeEqual {
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
