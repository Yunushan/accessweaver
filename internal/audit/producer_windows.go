//go:build windows

package audit

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessProducer pins the OS thread while checking for impersonation. An
// impersonation token or any token-query error refuses rather than attributing
// work to the process token as a fallback. No token or security context changes.
func requireProcessTokenContext() error {
	var thread windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &thread)
	if err == nil {
		_ = thread.Close()
		return ErrProcessIdentity
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return ErrProcessIdentity
	}
	return nil
}
func currentProcessPrincipal() (result processPrincipal, failure error) {
	if requireProcessTokenContext() != nil {
		return processPrincipal{}, ErrProcessIdentity
	}
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
		return processPrincipal{}, ErrProcessIdentity
	}
	defer func() {
		if token.Close() != nil {
			result = processPrincipal{}
			failure = ErrProcessIdentity
		}
	}()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return processPrincipal{}, ErrProcessIdentity
	}
	var elevated, size uint32
	if windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &size) != nil || size != uint32(unsafe.Sizeof(elevated)) {
		return processPrincipal{}, ErrProcessIdentity
	}
	if requireProcessTokenContext() != nil {
		return processPrincipal{}, ErrProcessIdentity
	}
	class := "user"
	if elevated != 0 {
		class = "administrator"
	}
	return processPrincipal{"sid", user.User.Sid.String(), class}, nil
}
