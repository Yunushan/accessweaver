package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

// Check keys before typed decode: encoding/json otherwise accepts duplicate or
// case-aliased field names. Snapshot members are all structs/slices/scalars.
func strictSnapshot(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := checkValue(decoder, reflect.TypeOf(Snapshot{}), 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing snapshot data")
	}
	return nil
}
func checkValue(decoder *json.Decoder, kind reflect.Type, depth int) error {
	if depth > 16 {
		return errors.New("snapshot nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	} // Typed decoding validates scalar types/timestamps.
	switch delimiter {
	case '{':
		if kind.Kind() != reflect.Struct {
			return errors.New("unexpected snapshot object")
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = field.Type
			}
		}
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate snapshot field")
			}
			field, ok := fields[name]
			if !ok {
				return errors.New("unknown snapshot field")
			}
			seen[name] = true
			if err := checkValue(decoder, field, depth+1); err != nil {
				return err
			}
		}
		if kind == reflect.TypeOf(Snapshot{}) && len(seen) != 3 {
			return errors.New("snapshot requires schemaVersion, createdAt and profiles")
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid snapshot object")
		}
	case '[':
		if kind.Kind() != reflect.Slice {
			return errors.New("unexpected snapshot array")
		}
		for decoder.More() {
			if err := checkValue(decoder, kind.Elem(), depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid snapshot array")
		}
	default:
		return errors.New("invalid snapshot delimiter")
	}
	return nil
}
