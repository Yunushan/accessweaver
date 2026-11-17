// Package privatefile creates exclusive user-selected files with private
// permissions before payload writes. It never repairs a preexisting object.
package privatefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// CreateTemp uses the same private-from-creation platform policy as Create.
// A pattern has at most one star and is one native filename component. Only
// exclusive name collisions retry; ACL/ownership/I/O failures preserve evidence.
func CreateTemp(dir, pattern string) (*os.File, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if pattern == "" || pattern == "." || pattern == ".." || len(pattern) > 128 || !utf8.ValidString(pattern) || filepath.Base(pattern) != pattern || filepath.IsAbs(pattern) || strings.IndexByte(pattern, 0) >= 0 || strings.Count(pattern, "*") > 1 {
		return nil, errors.New("invalid private temporary file pattern")
	}
	for attempt := 0; attempt < 8; attempt++ {
		var random [24]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		suffix := hex.EncodeToString(random[:])
		name := pattern + suffix
		if strings.Contains(pattern, "*") {
			name = strings.Replace(pattern, "*", suffix, 1)
		}
		file, err := Create(filepath.Join(dir, name))
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, os.ErrExist
}
