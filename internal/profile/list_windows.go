//go:build windows

package profile

import (
	"syscall"
	"unsafe"
)

var currentListThread = syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentThread")

var openListThreadToken = syscall.NewLazyDLL("advapi32.dll").NewProc("OpenThreadToken")

func canShareListRead() bool {
	var token syscall.Token
	// OpenAsSelf affects access to the token handle only; the presence of
	// any impersonation keeps the read on the caller's OS thread.
	thread, _, _ := currentListThread.Call()
	if thread == 0 {
		return false
	}
	ok, _, err := openListThreadToken.Call(thread, syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&token)))
	if ok != 0 {
		token.Close()
		return false
	}
	return err == syscall.Errno(1008) // ERROR_NO_TOKEN; other failures stay synchronous.
}
