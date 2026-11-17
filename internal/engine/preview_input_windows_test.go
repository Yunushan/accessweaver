//go:build windows

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/profile"
	"golang.org/x/sys/windows"
)

func TestWindowsPreviewLocalInputs(t *testing.T) {
	optIn := os.Getenv("ACCESSWEAVER_DISPOSABLE_WINDOWS_PREVIEW_TEST")
	if optIn == "" {
		t.Skip("requires explicit disposable hosted Windows preview fixture")
	}
	if optIn != "1" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" ||
		os.Getenv("ACCESSWEAVER_EXPECT_GOARCH") != runtime.GOARCH || os.Getenv("GOTOOLCHAIN") != "local" || runtime.Version() != "go"+os.Getenv("GO_VERSION") {
		t.Fatal("declared preview fixture requires exact native hosted source context")
	}
	directory := t.TempDir()
	binary := fixtureBinary(t, directory, "sing-box")
	config := filepath.Join(directory, "config.json")
	if os.WriteFile(config, []byte("{}"), 0600) != nil {
		t.Fatal("configuration fixture creation failed")
	}
	p := profile.New("preview-local", "Local preview", "sing-box")
	p.Binary, p.ConfigPath = binary, config
	digest := sha256.Sum256([]byte("inert adapter fixture"))
	p.SHA256 = hex.EncodeToString(digest[:])
	plan, err := Preview(p, directory)
	if err != nil || !plan.Ready {
		t.Fatal("local configuration or executable hash inspection failed")
	}

	t.Run("metadata-without-data-read", func(t *testing.T) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		observed, err := fileidentity.FromPath(binary, false)
		if err != nil || observed.Kind != fileidentity.Regular {
			t.Fatal("ACL fixture identity unavailable")
		}
		original, err := windows.GetNamedSecurityInfo(binary, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal("ACL fixture preimage unavailable")
		}
		originalDACL, _, err := original.DACL()
		if err != nil {
			t.Fatal("ACL fixture DACL unavailable")
		}
		control, _, err := original.Control()
		if err != nil {
			t.Fatal("ACL fixture control unavailable")
		}
		restore := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
		if control&windows.SE_DACL_PROTECTED != 0 {
			restore = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
		}
		t.Cleanup(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			current, err := fileidentity.FromPath(binary, false)
			if err != nil || current.ID != observed.ID {
				t.Error("ACL fixture binding changed; refusing restoration")
				return
			}
			if windows.SetNamedSecurityInfo(binary, windows.SE_FILE_OBJECT, restore, nil, nil, originalDACL, nil) != nil {
				t.Error("ACL fixture restoration failed")
			}
			runtime.KeepAlive(original)
		})
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || user.User.Sid == nil {
			t.Fatal("ACL fixture principal unavailable")
		}
		// Read attributes, execute, synchronize, read control and restoration-only
		// WRITE_DAC; no READ_DATA or READ_EA is granted. This is an owned temp file.
		restricted, err := windows.SecurityDescriptorFromString("D:P(A;;0x1600a0;;;" + user.User.Sid.String() + ")")
		if err != nil {
			t.Fatal("ACL fixture descriptor unavailable")
		}
		dacl, _, err := restricted.DACL()
		if err != nil || windows.SetNamedSecurityInfo(binary, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil) != nil {
			t.Fatal("ACL fixture restriction failed")
		}
		runtime.KeepAlive(restricted)
		opened, readErr := os.Open(binary)
		if opened != nil {
			_ = opened.Close()
			t.Fatal("ACL fixture did not deny file-data acquisition")
		}
		if !errors.Is(readErr, os.ErrPermission) {
			t.Fatal("ACL fixture denial was not established")
		}
		metadata, err := statPreviewInput(binary)
		if err != nil || !metadata.regular {
			t.Fatal("metadata inspection demanded file-data access")
		}
		candidate := p
		candidate.SHA256 = ""
		if local, err := Preview(candidate, directory); err != nil || !local.Ready {
			t.Fatal("metadata-only preview lost execute-only compatibility")
		}
		candidate.SHA256 = p.SHA256
		if pinned, err := Preview(candidate, directory); err != nil || pinned.Ready {
			t.Fatal("pinned hash inspection bypassed file-data permissions")
		}
	})
	t.Setenv("PATH", `\\preview-fixture.invalid\no-share`+";"+directory)
	p.Binary = "sing-box.exe"
	if plan, err = Preview(p, directory); err != nil || !plan.Ready || plan.Binary != binary {
		t.Fatal("local PATH selection failed")
	}
	for _, name := range []string{`\\preview-fixture.invalid\no-share\config.json`, `\\?\C:\config.json`, `\??\C:\config.json`} {
		if data, err := readConfigInputContext(context.Background(), name); data != nil || err == nil {
			t.Fatal("remote/device configuration was inspected")
		}
	}
	p.Binary = `\\preview-fixture.invalid\no-share\sing-box.exe`
	if plan, err = Preview(p, directory); err != nil || plan.Ready {
		t.Fatal("remote executable preview did not refuse")
	}
}
