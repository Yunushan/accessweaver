package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var errPrivateCreateAt = errors.New("private directory-relative file is unavailable")

type privateCreateAtError struct{ cause error }

func (e *privateCreateAtError) Error() string { return errPrivateCreateAt.Error() }
func (e *privateCreateAtError) Unwrap() error { return e.cause }
func privateCreateAtFailure(cause error) error {
	return &privateCreateAtError{cause: errors.Join(errPrivateCreateAt, cause)}
}

// A portable safe leaf has no alternate stream, path or reserved-device spelling.
// The parent name is never reconstructed and used as filesystem authority.
func privateCreateAtLeaf(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || filepath.Base(name) != name || !filepath.IsLocal(name) || strings.ContainsAny(name, "<>:\"/\\|?*") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for _, ch := range name {
		if ch < 32 {
			return false
		}
	}
	stem := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return false
	}
	if strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT") {
		switch stem[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return false
		}
	}
	return true
}

func privateCreateAtParent(parent *os.File, name string) error {
	if parent == nil || !privateCreateAtLeaf(name) {
		return privateCreateAtFailure(nil)
	}
	return nil
}
