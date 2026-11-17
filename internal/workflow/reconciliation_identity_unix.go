//go:build !windows

package workflow

import (
	"os"
	"syscall"
)

func reconciliationLinkCount(file *os.File) (uint64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, ErrLifecycleReconciliationUnavailable
	}
	return uint64(stat.Nlink), nil
}
