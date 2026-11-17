package workflow

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeDesktopAdmissionRefusesElevatedToken(t *testing.T) {
	if err := requireAdministrator(); err != nil {
		t.Skip("this admission check requires an elevated Windows test process")
	}
	const denied = "apply from an unelevated Windows desktop session as the signed-in user"
	if err := requireDesktopUser(); err == nil || err.Error() != denied {
		t.Fatalf("expected the native desktop-token refusal, got %v", err)
	}
}

func TestNativeUserApplicationNoOpAvoidsMachineStorage(t *testing.T) {
	if err := requireDesktopUser(); err != nil {
		t.Skip("user application acceptance requires an unelevated desktop token")
	}
	root := t.TempDir()
	apps := filepath.Join(root, "empty-apps")
	machine := filepath.Join(root, "machine-storage-must-not-be-created")
	if err := os.Mkdir(apps, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", apps)
	t.Setenv("ProgramData", machine)
	dir := filepath.Join(root, "job")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Discord is absent from the isolated application directory. This executes
	// the real embedded dispatcher without stopping or uninstalling a host app.
	result, err := execute(ctx, dir, Request{Action: "app-remove", Engine: "discord"})
	if err != nil {
		t.Fatal(err, string(result))
	}
	var outcome struct {
		OK      bool   `json:"ok"`
		Journal string `json:"journal"`
		Data    struct {
			Application string `json:"application"`
			Removed     *bool  `json:"removed"`
		} `json:"data"`
	}
	if err = json.Unmarshal(result, &outcome); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "application", "logs", "application.json")
	if !outcome.OK || outcome.Journal != journal {
		t.Fatalf("user operation did not retain a local journal: %+v", outcome)
	}
	if outcome.Data.Application != "discord" || outcome.Data.Removed == nil || *outcome.Data.Removed {
		t.Fatalf("absent application did not return a verified no-op: %+v", outcome.Data)
	}
	if _, err = os.Stat(journal); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(machine); !os.IsNotExist(err) {
		t.Fatalf("user operation touched machine storage: %v", err)
	}
}
