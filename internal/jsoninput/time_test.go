package jsoninput

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestTimestampSyntaxAndSerializableMeaning(t *testing.T) {
	for _, value := range []string{"2026-11-01T12:00:00Z", "2026-11-01T12:00:00.123456789Z", "2026-11-01T12:00:00+00:00", "2026-11-01T12:00:00+23:59", "2026-11-01T12:00:00-23:59", "0001-01-01T00:00:00Z"} {
		if !ValidTimestamp(value) {
			t.Fatal("valid RFC3339 timestamp rejected")
		}
	}
	for _, value := range []string{"2026-11-01T12:00:00+24:00", "2026-11-01T12:00:00-24:00", "2026-11-01T12:00:00+00:60", "2026-11-01T12:00:00,123Z", "2026-11-01T9:00:00Z", "2026-02-30T12:00:00Z", "2026-11-01 12:00:00Z", "2026-11-01T12:00:60Z"} {
		if ValidTimestamp(value) {
			t.Fatal("invalid RFC3339 timestamp accepted")
		}
		original := inputFixture{Name: "unchanged", At: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
		got := original
		data, _ := json.Marshal(map[string]string{"at": value})
		if !errors.Is(Decode(data, &got), ErrInvalid) || !reflect.DeepEqual(got, original) {
			t.Fatal("invalid timestamp was published or changed the destination")
		}
	}
}
