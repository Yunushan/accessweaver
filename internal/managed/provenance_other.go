//go:build !windows && (!linux || (!amd64 && !arm64))

package managed

import "errors"

func checkProtectedInput(path, digest string, directory bool) error {
	return errors.New("native managed-input protection is not implemented on this platform")
}
