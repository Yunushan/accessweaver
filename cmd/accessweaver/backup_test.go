package main

import (
	"context"
	"github.com/Yunushan/accessweaver/internal/profile"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBackupCLICreateInspectRestoreAndRefuseOverwrite(t *testing.T) {
	workspace := t.TempDir()
	root := filepath.Join(workspace, "source")
	t.Setenv("ACCESSWEAVER_HOME", root)
	store, err := profile.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	p := profile.New("private-profile", "PRIVATE_BACKUP_NAME", "byedpi")
	p.Args = []string{"PRIVATE_BACKUP_ARGUMENT"}
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	before, err := store.SnapshotContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	password := filepath.Join(workspace, "password.txt")
	if err := os.WriteFile(password, []byte("long test-only passphrase\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(workspace, "profiles.awbackup")
	create := []string{"backup", "create", "--out", archive, "--passphrase-file", password}
	if err := execute(create); err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), p.Name) {
		t.Fatal("plaintext profile in archive")
	}
	if err := execute(create); err == nil {
		t.Fatal("existing output overwritten")
	}
	current, err := os.ReadFile(archive)
	if err != nil || string(current) != string(encrypted) {
		t.Fatal("failed output changed archive", err)
	}
	if err := execute([]string{"backup", "inspect", "--archive", archive, "--passphrase-file", password}); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(workspace, "recovered")
	restore := []string{"backup", "restore", "--archive", archive, "--passphrase-file", password, "--into", destination}
	if err := execute(restore); err != nil {
		t.Fatal(err)
	}
	restored, err := profile.NewStore(destination)
	if err != nil {
		t.Fatal(err)
	}
	after, err := restored.SnapshotContext(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("CLI restore changed profiles", err)
	}
	if err := execute(restore); err == nil {
		t.Fatal("existing restored data replaced")
	}
	if err := execute([]string{"backup", "create", "--out", filepath.Join(root, "profiles", "invalid.json"), "--passphrase-file", password}); err == nil {
		t.Fatal("backup created inside profile source")
	}
	if err := os.WriteFile(password, []byte("a different incorrect password"), 0600); err != nil {
		t.Fatal(err)
	}
	failedDestination := filepath.Join(workspace, "wrong-password")
	err = execute([]string{"backup", "restore", "--archive", archive, "--passphrase-file", password, "--into", failedDestination})
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatal(err)
	}
	if _, err := os.Stat(failedDestination); !os.IsNotExist(err) {
		t.Fatal("unauthenticated restore created state", err)
	}
}
func TestBackupInvalidOptionsAndMissingSourceDoNotCreateState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	t.Setenv("ACCESSWEAVER_HOME", root)
	for _, args := range [][]string{
		{"backup"}, {"backup", "unknown"}, {"backup", "create", "--password", "DO_NOT_PRINT_PASSWORD"},
		{"backup", "restore", "--archive", "missing", "--into", root},
	} {
		err := execute(args)
		if err == nil || strings.Contains(err.Error(), "DO_NOT_PRINT_PASSWORD") {
			t.Fatal("invalid options or secret handling", err)
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("backup option error created profile data", err)
	}
}
