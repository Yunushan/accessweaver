//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

import "errors"

func LaunchInstalled(args []string) error {
	return errors.New("versioned application launching requires macOS")
}
