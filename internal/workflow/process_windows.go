//go:build windows

package workflow

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Yunushan/accessweaver/internal/nativeprocess"
)

func configureCommand(cmd *exec.Cmd) commandOwner {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	owner := nativeprocess.NewTreeOwner()
	cmd.Cancel = owner.Cancel
	return owner
}

const (
	tokenSessionID       = 12
	tokenElevation       = 20
	userObjectFlags      = 1
	visibleWindowStation = 1
)

var (
	workflowUser32                   = windows.NewLazySystemDLL("user32.dll")
	getWorkflowWindowStation         = workflowUser32.NewProc("GetProcessWindowStation")
	getWorkflowUserObjectInformation = workflowUser32.NewProc("GetUserObjectInformationW")
)

func tokenDWORD(token syscall.Token, class uint32) (uint32, error) {
	var value, size uint32
	const valueSize = uint32(unsafe.Sizeof(value))
	if err := syscall.GetTokenInformation(token, class, (*byte)(unsafe.Pointer(&value)), valueSize, &size); err != nil {
		return 0, err
	}
	if size != valueSize {
		return 0, errors.New("invalid Windows token information size")
	}
	return value, nil
}

func requireAdministrator() error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("cannot inspect administrator access: %w", err)
	}
	defer token.Close()
	elevated, err := tokenDWORD(token, tokenElevation)
	if err != nil {
		return fmt.Errorf("cannot inspect administrator access: %w", err)
	}
	if elevated == 0 {
		return errors.New("machine changes require a separately elevated system apply CLI; export the reviewed request and keep the dashboard unelevated")
	}
	return nil
}

func requireDesktopUser() error {
	denied := errors.New("apply from an unelevated Windows desktop session as the signed-in user")
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("cannot inspect Windows desktop access: %w", err)
	}
	defer token.Close()
	elevated, err := tokenDWORD(token, tokenElevation)
	if err != nil {
		return fmt.Errorf("cannot inspect Windows desktop elevation: %w", err)
	}
	if elevated != 0 {
		return denied
	}
	session, err := tokenDWORD(token, tokenSessionID)
	if err != nil {
		return fmt.Errorf("cannot inspect the Windows logon session: %w", err)
	}
	if session == 0 {
		return denied
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("cannot inspect the Windows desktop user: %w", err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return fmt.Errorf("cannot identify the Windows desktop user: %w", err)
	}
	if sid == "S-1-5-18" {
		return denied
	}
	// The process owns this association. GetProcessWindowStation returns a borrowed handle.
	station, _, stationErr := getWorkflowWindowStation.Call()
	if station == 0 {
		return fmt.Errorf("cannot inspect the Windows window station: %w", stationErr)
	}
	var flags struct {
		inherit  uint32
		reserved uint32
		value    uint32
	}
	ok, _, flagsErr := getWorkflowUserObjectInformation.Call(station, userObjectFlags,
		uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), 0)
	if ok == 0 {
		return fmt.Errorf("cannot inspect Windows window station visibility: %w", flagsErr)
	}
	if flags.value&visibleWindowStation == 0 {
		return denied
	}
	return nil
}
