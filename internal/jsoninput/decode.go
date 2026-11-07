// Package jsoninput validates the bounded JSON objects accepted by desktop
// requests and profile imports before publishing any typed value.
package jsoninput

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxBytes = 1 << 20
const maxDepth = 16

var ErrInvalid = errors.New("invalid JSON input: require one object with unique canonical field names and valid values")
var ErrTooLarge = errors.New("JSON input exceeds 1 MiB")

// Public text never includes input values or field names; native decode causes
// remain available to errors.Is/As for local inspection.
type inputError struct{ cause error }

func (e *inputError) Error() string        { return ErrInvalid.Error() }
func (e *inputError) Unwrap() error        { return e.cause }
func (e *inputError) Is(target error) bool { return target == ErrInvalid }

var rawType = reflect.TypeFor[json.RawMessage]()
var timeType = reflect.TypeFor[time.Time]()

// Decode accepts an object with exact schema keys, including exported embedded
// structs. Null slices, maps, pointers and timestamps retain their existing JSON
// meanings; null scalar/struct fields do not silently become zero values.
// The destination is replaced only after the entire document has been checked.
func Decode(data []byte, target any) error {
	if len(data) > MaxBytes {
		return ErrTooLarge
	}
	value := reflect.ValueOf(target)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return &inputError{errors.New("JSON destination must be a nonnil pointer")}
	}
	shape := value.Elem().Type()
	if shape.Kind() != reflect.Struct && shape.Kind() != reflect.Map {
		return &inputError{errors.New("JSON destination must describe an object")}
	}
	if !utf8.Valid(data) {
		return &inputError{errors.New("JSON input is not UTF-8")}
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return &inputError{errors.New("JSON input must be an object")}
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	tokens.UseNumber()
	if err := checkValue(tokens, shape, 0); err != nil {
		return &inputError{err}
	}
	if _, err := tokens.Token(); err != io.EOF {
		return &inputError{errors.New("JSON input has trailing data")}
	}
	next := reflect.New(shape)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(next.Interface()); err != nil {
		return &inputError{err}
	}
	value.Elem().Set(next.Elem())
	return nil
}

func objectFields(shape reflect.Type, fields map[string]reflect.Type, depth int) error {
	if depth > maxDepth {
		return errors.New("JSON schema nesting exceeds limit")
	}
	for i := 0; i < shape.NumField(); i++ {
		field := shape.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" && field.Anonymous {
			embedded := field.Type
			if embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				if err := objectFields(embedded, fields, depth+1); err != nil {
					return err
				}
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		if _, exists := fields[name]; exists {
			return errors.New("ambiguous JSON schema field")
		}
		fields[name] = field.Type
	}
	return nil
}

func checkValue(decoder *json.Decoder, shape reflect.Type, depth int) error {
	if depth > maxDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	if shape == rawType {
		shape = nil
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if shape == nil || shape == timeType {
			return nil
		}
		switch shape.Kind() {
		case reflect.Pointer, reflect.Map, reflect.Slice:
			return nil
		}
		return errors.New("null does not match JSON schema")
	}
	for shape != nil && shape.Kind() == reflect.Pointer {
		shape = shape.Elem()
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		if shape == timeType {
			value, ok := token.(string)
			if !ok || !ValidTimestamp(value) {
				return errors.New("timestamp must use valid RFC3339 syntax")
			}
		}
		if shape != nil && shape != timeType {
			switch shape.Kind() {
			case reflect.Struct, reflect.Map, reflect.Slice, reflect.Array:
				return errors.New("scalar does not match JSON schema")
			}
		}
		return nil // The typed decoder checks exact scalar and timestamp types.
	}
	switch delimiter {
	case '{':
		var fields map[string]reflect.Type
		var element reflect.Type
		if shape != nil {
			switch shape.Kind() {
			case reflect.Struct:
				fields = make(map[string]reflect.Type)
				if err := objectFields(shape, fields, 0); err != nil {
					return err
				}
			case reflect.Map:
				if shape.Key().Kind() != reflect.String {
					return errors.New("unsupported JSON map key")
				}
				element = shape.Elem()
			default:
				return errors.New("object does not match JSON schema")
			}
		}
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate JSON field")
			}
			seen[name] = true
			child := element
			if fields != nil {
				var exists bool
				child, exists = fields[name]
				if !exists {
					return errors.New("unknown or noncanonical JSON field")
				}
			}
			if err := checkValue(decoder, child, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		var element reflect.Type
		if shape != nil {
			if shape.Kind() != reflect.Slice && shape.Kind() != reflect.Array {
				return errors.New("array does not match JSON schema")
			}
			element = shape.Elem()
		}
		for decoder.More() {
			if err := checkValue(decoder, element, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
