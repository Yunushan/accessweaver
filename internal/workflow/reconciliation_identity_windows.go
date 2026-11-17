//go:build windows

package workflow

import (
	"golang.org/x/sys/windows"
	"os"
)

func reconciliationLinkCount(file *os.File) (uint64, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}
	var info windows.ByHandleFileInformation
	var callErr error
	err = raw.Control(func(fd uintptr) { callErr = windows.GetFileInformationByHandle(windows.Handle(fd), &info) })
	if err != nil {
		return 0, err
	}
	if callErr != nil {
		return 0, callErr
	}
	return uint64(info.NumberOfLinks), nil
}
