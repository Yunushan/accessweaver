//go:build windows

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Yunushan/accessweaver/internal/profile"
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
