//go:build !windows && !darwin

package privatefile

import "os"

// CreateAt creates a new private regular file in the actual retained directory.
// It borrows parent, never follows a leaf link, and never removes a possible
// newly created empty file on verification failure. The caller owns the result.
func CreateAt(parent *os.File, name string) (*os.File, error) {
	return createAtUnix(parent, name, nil)
}
