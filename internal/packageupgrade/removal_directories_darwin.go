//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"errors"
	"os"
	"path"
	"syscall"
)

// The explicit "." plan object names the recorded root inside its fixed
// protected parent. No caller path or recursive removal operation is accepted.
func removalObjectName(root removalPlanRoot, object removalPlanObject) string {
	if object.Path == "." {
		if root.Kind == "public" {
			return removalQuarantineName
		}
		return root.Key
	}
	return path.Base(object.Path)
}

func verifyEmptyRemovalDirectory(parent *os.File, name string, held *os.File, want removalPlanObject) error {
	if held == nil || want.Kind != "directory" || want.Mode != "0755" {
		return errors.New("invalid removal directory target")
	}
	if e := deploymentObject(held, true, 0, 0755); e != nil {
		return e
	}
	info, e := held.Stat()
	if e != nil {
		return e
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != want.Device || st.Ino != want.Inode {
		return errors.New("removal directory identity changed")
	}
	entries, e := deploymentEntries(held, 0, 0)
	if e != nil {
		return e
	}
	if len(entries) != 0 {
		return errors.New("removal directory is not empty")
	}
	return sameDeploymentEntry(parent, name, held, 0)
}
