package jsoninput

import (
	"regexp"
	"time"
)

// The standard timestamp parser has a permissive fallback for offsets such as
// +24:00 and comma fractions. Validate RFC3339 syntax before accepting typed time.
var timestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// ValidTimestamp accepts calendar-valid RFC3339 text that can be serialized again.
func ValidTimestamp(value string) bool {
	if !timestampPattern.MatchString(value) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return false
	}
	_, err = parsed.MarshalJSON()
	return err == nil
}
