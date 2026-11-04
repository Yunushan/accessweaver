// Package fileidentity obtains native object identity for in-process alias
// comparisons. An identity is neither a permission grant nor a durable name.
package fileidentity

import (
	"errors"
	"os"
	"time"
)

// ErrUnavailable deliberately contains no pathname, SID, or native error.
var ErrUnavailable = errors.New("native file identity unavailable")

// ID is comparable. Windows preserves the full volume serial and 128-bit file
// identifier; Unix preserves the native device and inode without narrowing.
// Values are meaningful only for live in-process comparisons.
type ID struct {
	Volume uint64
	FileID [16]byte
}

type Kind uint8

const (
	Regular Kind = iota + 1
	Directory
	Reparse
	Other
)

// State is one metadata observation, not an authorization or immutability claim.
type State struct {
	ID       ID
	Kind     Kind
	Size     int64
	Modified time.Time
}

// FromFile borrows file and retains its descriptor throughout the query. It
// never reads data, changes the offset, closes file, or changes its permissions.
func FromFile(file *os.File) (State, error) { return fromFile(file) }

// FromPath obtains metadata only. Ordinary relative names are accepted. The
// followLinks argument selects whether a final symlink/reparse point is followed;
// intermediate directory links are resolved. No probe survives this call. Only
// genuine absence returns os.ErrNotExist; all other failures are redacted.
func FromPath(path string, followLinks bool) (State, error) { return fromPath(path, followLinks) }
