package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

var errExecutableHashUnavailable = errors.New("executable hash could not be confirmed; not launched")

type executableHashFailure struct{ cause error }

func (e *executableHashFailure) Error() string { return errExecutableHashUnavailable.Error() }
func (e *executableHashFailure) Unwrap() []error {
	return []error{errExecutableHashUnavailable, e.cause}
}

// The caller transfers one already-open reader. Publish no digest until its
// checked Close returns. A body panic propagates after that same Close attempt.
// This checks the observed stream only, not the image a later exec may reopen.
func executableHash(reader io.ReadCloser) (digest string, failure error) {
	defer func() {
		closeErr := reader.Close()
		if failure != nil || closeErr != nil {
			digest = ""
			failure = &executableHashFailure{cause: errors.Join(failure, closeErr)}
		}
	}()
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
