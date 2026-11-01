//go:build windows

package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var getManagedDriveType = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDriveTypeW")

var getNamedMachineSecurity = securityDLL.NewProc("GetNamedSecurityInfoW")

const ancestorMutationRights uint32 = 0x500d0152
const fileMutationRights uint32 = ancestorMutationRights | 0x4 | 0x40

func checkProtectedPath(path string, directory bool, mask uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	attrs, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || attrs.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed input uses a reparse point")
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("managed input has the wrong file type")
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var owner, acl, descriptor unsafe.Pointer
	code, _, _ := getNamedMachineSecurity.Call(uintptr(unsafe.Pointer(name)), 1, 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if code != 0 {
		return syscall.Errno(code)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(descriptor)))
	return checkMachineDescriptor(owner, acl, mask)
}

func checkProtectedInput(path, digest string, directory bool) error {
	volume := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || len(volume) != 2 || volume[1] != ':' || strings.Contains(path[2:], ":") {
		return errors.New("managed inputs require an absolute local drive path without streams")
	}
	drive, _ := syscall.UTF16PtrFromString(volume + `\`)
	kind, _, _ := getManagedDriveType.Call(uintptr(unsafe.Pointer(drive)))
	if kind != 3 {
		return errors.New("managed inputs require a fixed local drive")
	}
	path = filepath.Clean(path)
	parent := filepath.Dir(path)
	ancestors := []string{}
	for {
		ancestors = append(ancestors, parent)
		next := filepath.Dir(parent)
		if next == parent {
			break
		}
		parent = next
	}
	// Validate from the volume down before following each child path. Creation
	// of an unrelated subdirectory on a trusted ancestor grants no replacement.
	for i := len(ancestors) - 1; i >= 0; i-- {
		if err := checkProtectedPath(ancestors[i], true, ancestorMutationRights); err != nil {
			return fmt.Errorf("untrusted managed parent: %w", err)
		}
	}
	if err := checkProtectedPath(path, directory, fileMutationRights); err != nil {
		return err
	}
	root := path
	if !directory {
		root = filepath.Dir(path)
	}
	// Also reject writable DLL/assets adjacent to an approved executable/config.
	type pendingDirectory struct {
		path  string
		depth int
	}
	pending := []pendingDirectory{{root, 0}}
	count := 0
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current.depth > 32 {
			return errors.New("managed input directory exceeds 32 levels")
		}
		if err := checkProtectedPath(current.path, true, fileMutationRights); err != nil {
			return err
		}
		folder, err := os.Open(current.path)
		if err != nil {
			return err
		}
		for {
			entries, readErr := folder.ReadDir(128)
			for _, entry := range entries {
				count++
				if count > 4096 {
					folder.Close()
					return errors.New("managed input directory exceeds 4096 entries")
				}
				item := filepath.Join(current.path, entry.Name())
				if err := checkProtectedPath(item, entry.IsDir(), fileMutationRights); err != nil {
					folder.Close()
					return err
				}
				if entry.IsDir() {
					pending = append(pending, pendingDirectory{item, current.depth + 1})
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				folder.Close()
				return readErr
			}
		}
		if err := folder.Close(); err != nil {
			return err
		}
	}
	if digest == "" {
		return nil
	}
	if directory || !digestPattern.MatchString(digest) {
		return errors.New("managed file content requires a SHA-256 digest")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(f, (512<<20)+1))
	if err != nil {
		return err
	}
	if size > 512<<20 {
		return errors.New("managed input exceeds 512 MiB")
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("managed input SHA-256 mismatch")
	}
	return nil
}
