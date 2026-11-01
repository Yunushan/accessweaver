//go:build windows

package nativepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Yunushan/accessweaver/internal/wintrust"
)

var systemDirectory = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")

func SystemDirectory() (string, error) {
	buffer := make([]uint16, 32768)
	size, _, err := systemDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if size == 0 {
		return "", err
	}
	if size >= uintptr(len(buffer)) {
		return "", errors.New("Windows system directory exceeds limit")
	}
	return syscall.UTF16ToString(buffer[:size]), nil
}

// The all-users directory API expands SystemDrive from the caller environment.
// Read its protected machine setting and expand only OS-derived variables instead.
func ProgramData() (string, error) {
	variables, err := systemVariables()
	if err != nil {
		return "", err
	}
	return machineDirectory(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, "ProgramData", variables)
}
func systemVariables() (map[string]string, error) {
	system, err := SystemDirectory()
	if err != nil {
		return nil, err
	}
	return map[string]string{"SYSTEMDRIVE": filepath.VolumeName(system), "SYSTEMROOT": filepath.Dir(system), "WINDIR": filepath.Dir(system)}, nil
}
func machineDirectory(registryPath, valueName string, substitutions map[string]string) (string, error) {
	name, _ := syscall.UTF16PtrFromString(registryPath)
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, name, 0, syscall.KEY_READ|syscall.KEY_WOW64_64KEY, &key); err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(key)
	if err := wintrust.CheckHandle(key, 4, wintrust.RegistryMutationRights); err != nil {
		return "", fmt.Errorf("untrusted Windows directory setting: %w", err)
	}
	value, _ := syscall.UTF16PtrFromString(valueName)
	var kind, size uint32
	if err := syscall.RegQueryValueEx(key, value, nil, &kind, nil, &size); err != nil {
		return "", err
	}
	if size < 2 || size > 65536 || size%2 != 0 {
		return "", errors.New("invalid Windows directory setting size")
	}
	buffer := make([]uint16, size/2)
	if err := syscall.RegQueryValueEx(key, value, nil, &kind, (*byte)(unsafe.Pointer(&buffer[0])), &size); err != nil {
		return "", err
	}
	if size < 2 || size%2 != 0 || size > uint32(len(buffer)*2) || (kind != syscall.REG_SZ && kind != syscall.REG_EXPAND_SZ) {
		return "", errors.New("invalid Windows directory setting type")
	}
	buffer = buffer[:size/2]
	if buffer[len(buffer)-1] != 0 {
		return "", errors.New("unterminated Windows directory setting")
	}
	for _, unit := range buffer[:len(buffer)-1] {
		if unit == 0 {
			return "", errors.New("embedded NUL in Windows directory setting")
		}
	}
	path := syscall.UTF16ToString(buffer)
	if kind == syscall.REG_EXPAND_SZ {
		unknown := false
		path = regexp.MustCompile(`%[^%]+%`).ReplaceAllStringFunc(path, func(variable string) string {
			expanded, ok := substitutions[strings.ToUpper(strings.Trim(variable, "%"))]
			if !ok {
				unknown = true
			}
			return expanded
		})
		if unknown || strings.Contains(path, "%") {
			return "", errors.New("unsupported variable in Windows directory setting")
		}
	}
	volume := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || len(volume) != 2 || volume[1] != ':' || strings.Contains(path[2:], ":") || strings.ContainsAny(path, "\x00\r\n") {
		return "", errors.New("Windows machine directory is not a local absolute path")
	}
	return filepath.Clean(path), nil
}
func UtilityEnvironment() ([]string, error) {
	system, err := SystemDirectory()
	if err != nil {
		return nil, err
	}
	windows := filepath.Dir(system)
	powershell := filepath.Join(system, "WindowsPowerShell", "v1.0")
	return cleanEnvironment(os.Environ(), []string{"SystemRoot=" + windows, "WINDIR=" + windows, "SystemDrive=" + filepath.VolumeName(system), "ComSpec=" + filepath.Join(system, "cmd.exe"), "PATH=" + system + ";" + windows + ";" + powershell, "PSModulePath=" + filepath.Join(powershell, "Modules")}), nil
}
func ProcessEnvironment() ([]string, error) {
	environment, err := UtilityEnvironment()
	if err != nil {
		return nil, err
	}
	data, err := ProgramData()
	if err != nil {
		return nil, err
	}
	variables, err := systemVariables()
	if err != nil {
		return nil, err
	}
	key := `SOFTWARE\Microsoft\Windows\CurrentVersion`
	programs, err := machineDirectory(key, "ProgramFilesDir", variables)
	if err != nil {
		return nil, err
	}
	programs86, err := machineDirectory(key, "ProgramFilesDir (x86)", variables)
	if err != nil {
		return nil, err
	}
	variables["PROGRAMFILES"] = programs
	variables["PROGRAMFILES(X86)"] = programs86
	common, err := machineDirectory(key, "CommonFilesDir", variables)
	if err != nil {
		return nil, err
	}
	common86, err := machineDirectory(key, "CommonFilesDir (x86)", variables)
	if err != nil {
		return nil, err
	}
	return append(environment, "ProgramData="+data, "ALLUSERSPROFILE="+data, "ProgramFiles="+programs, "ProgramFiles(x86)="+programs86, "ProgramW6432="+programs,
		"CommonProgramFiles="+common, "CommonProgramFiles(x86)="+common86, "CommonProgramW6432="+common), nil
}
