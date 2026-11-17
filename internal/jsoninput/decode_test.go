package jsoninput

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type InputProbe struct {
	TLS  bool `json:"tls"`
	Port int  `json:"port"`
}
type inputFixture struct {
	Name string `json:"name"`
	InputProbe
	Nested InputProbe `json:"nested"`
	Args   []string   `json:"args"`
	At     time.Time  `json:"at"`
}

func TestCanonicalObjectRejectsAmbiguityBeforePublishing(t *testing.T) {
	for _, data := range []string{
		`{"name":"first","name":"second"}`,
		`{"name":"same","\u006eame":"same"}`,
		`{"Name":"case alias"}`, `{"NAME":"case alias"}`,
		`{"nested":{"tls":false,"tls":true}}`, `{"nested":{"TLS":false}}`,
		`{"tls":false,"TLS":true}`, `{"unknown":"PRIVATE_UNKNOWN_FIELD_VALUE"}`,
		`{"name":null}`, `{"tls":null}`, `{"nested":null}`,
		`{"name":"partial","port":"PRIVATE_WRONG_TYPE"}`,
		`{"name":"partial","at":"PRIVATE_BAD_TIMESTAMP"}`,
		`{"args":[null]}`, `{"nested":[]}`, `{"args":{}}`,
		`{"args":[],"nested":{"port":443}} {}`, `{"name":"partial"`,
		`null`, `[]`, `"string"`, `{"name":"` + string([]byte{0xff}) + `"}`,
	} {
		original := inputFixture{Name: "unchanged", InputProbe: InputProbe{TLS: true, Port: 42}, Args: []string{"untouched"}}
		got := original
		err := Decode([]byte(data), &got)
		if !errors.Is(err, ErrInvalid) || err.Error() != ErrInvalid.Error() || !reflect.DeepEqual(got, original) {
			t.Fatal("invalid input was accepted, disclosed, or partially published")
		}
	}
}

func TestCanonicalObjectPreservesSupportedShapesAndCauses(t *testing.T) {
	data := []byte(`{"name":"Yunus \u00c7","tls":false,"port":443,"nested":{"tls":true,"port":80},"args":null,"at":"2026-11-07T12:34:56.123456789+03:00"}`)
	var got inputFixture
	if Decode(data, &got) != nil || got.Name != "Yunus Ç" || got.TLS || got.Port != 443 || !got.Nested.TLS || got.Args != nil || got.At.Nanosecond() != 123456789 {
		t.Fatal("canonical object changed supported field meaning")
	}
	err := Decode([]byte(`{"port":"PRIVATE_WRONG_TYPE"}`), &got)
	var typeError *json.UnmarshalTypeError
	if !errors.As(err, &typeError) || !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("native cause or fixed public error text lost")
	}
	for _, target := range []any{nil, (*inputFixture)(nil), inputFixture{}, new(string)} {
		if !errors.Is(Decode([]byte(`{}`), target), ErrInvalid) {
			t.Fatal("invalid schema accepted")
		}
	}
	var raw map[string]json.RawMessage
	if Decode([]byte(`{}`), &raw) != nil || raw == nil || len(raw) != 0 {
		t.Fatal("empty object request rejected")
	}
	for _, body := range []string{`{"a":{"nested":1,"nested":2}}`, `{"a":[{"b":false,"\u0062":true}]}`} {
		if !errors.Is(Decode([]byte(body), &raw), ErrInvalid) || len(raw) != 0 {
			t.Fatal("raw-map subtree duplicate was published")
		}
	}
	if !errors.Is(Decode([]byte(`{"name":"`+strings.Repeat("x", MaxBytes)+`"}`), &got), ErrTooLarge) {
		t.Fatal("byte budget was not enforced")
	}
	if !errors.Is(Decode([]byte(`{"a":`+strings.Repeat("[", 20)+`0`+strings.Repeat("]", 20)+`}`), &raw), ErrInvalid) {
		t.Fatal("raw nesting budget was not enforced")
	}
}

func FuzzDecodeCanonicalObject(f *testing.F) {
	for _, seed := range [][]byte{[]byte(`{}`), []byte(`{"name":"fixture","tls":false,"nested":{"port":443},"args":["a"],"at":null}`), []byte(`{"name":"one","name":"two"}`), []byte(`{"args":null}`), []byte(`{"at":"2026-11-07T12:34:56+00:00"}`), {0xff}, []byte(`null`)} {
		f.Add(seed)
	}
	f.Add([]byte(`{"at":"\u0032026-11-07T12:34:56Z"}`))
	f.Add([]byte(`{"at":"2026-11-07T12\u003a34:56.123456789+03:00"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		original := inputFixture{Name: "unchanged", InputProbe: InputProbe{TLS: true, Port: 7}}
		got := original
		err := Decode(data, &got)
		if !bytes.Equal(data, before) {
			t.Fatal("decoder changed input bytes")
		}
		if err != nil {
			if !reflect.DeepEqual(got, original) {
				t.Fatal("failed decode changed destination")
			}
			return
		}
		encoded, err := json.Marshal(got)
		var roundtrip inputFixture
		if err != nil || Decode(encoded, &roundtrip) != nil || !sameFixture(roundtrip, got) {
			t.Fatal("accepted object did not round trip")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) != nil {
			t.Fatal("accepted object did not parse independently")
		}
		at := fields["at"]
		if len(at) == 0 {
			at = json.RawMessage("null")
		}
		payload := bytes.TrimSpace(data)
		opaque := append(append(append([]byte(`{"at":`), at...), []byte(`,"payload":`)...), payload...)
		opaque = append(opaque, '}')
		if len(opaque) <= MaxBytes {
			var preserved struct {
				At      time.Time       `json:"at"`
				Payload json.RawMessage `json:"payload"`
			}
			if Decode(opaque, &preserved) != nil || !preserved.At.Equal(got.At) || !bytes.Equal(preserved.Payload, payload) {
				t.Fatal("accepted timestamp decoding changed opaque payload bytes")
			}
		}
		keys := make([]string, 0, len(fields))
		for key := range fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			return
		}
		key, _ := json.Marshal(keys[0])
		trimmed := bytes.TrimSpace(data)
		duplicate := append(append(append(append([]byte{'{'}, key...), ':'), fields[keys[0]]...), ',')
		duplicate = append(duplicate, trimmed[1:]...)
		if !errors.Is(Decode(duplicate, &roundtrip), ErrInvalid) {
			t.Fatal("duplicate injection accepted")
		}
	})
}

// Location representations can differ while the timestamp is identical.
func sameFixture(a, b inputFixture) bool {
	if !a.At.Equal(b.At) {
		return false
	}
	a.At, b.At = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}
