//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// Called only by the explicitly opted-in hosted native policy worker after the
// root setup fixture enrolls revision3. The source-built worker runs as UID/GID
// 65534; no installed product, engine or browser is executed by this probe.
func linuxRequiredProfileAuditProbe(t *testing.T, p profile.Profile) {
	t.Helper()
	linuxNativeContext(t)
	if os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 || os.Getegid() != 65534 {
		t.Fatal("required-audit probe identity differs")
	}
	status, err := managed.MachineStatus()
	if err != nil || !status.Valid || status.Revision != 3 {
		t.Fatal("required-audit native policy unavailable", err)
	}
	base := os.Getenv("ACCESSWEAVER_LINUX_POLICY_AUDIT_ROOT")
	if base == "" || !filepath.IsAbs(base) || filepath.Clean(base) != base || filepath.Base(base) != "recorded-profile-worker" || filepath.Dir(filepath.Dir(base)) != "/etc" {
		t.Fatal("required-audit fixture root differs")
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("required-audit fixture root is not private")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != 65534 || native.Gid != 65534 {
		t.Fatal("required-audit fixture root ownership differs")
	}
	// User-root selection must not select the machine policy, which stays at
	// /etc/accessweaver through the normal production Current/Guard paths.
	root := filepath.Join(base, "state")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	t.Setenv("ACCESSWEAVER_HOME", root)
	input := os.Getenv("ACCESSWEAVER_LINUX_POLICY_PROFILE")
	if err := execute([]string{"import", input}); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("unrecorded CLI import did not refuse", err)
	}
	store, err := profile.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := store.List()
	if err != nil || len(profiles) != 0 {
		t.Fatal("unrecorded import changed profile content", err)
	}
	if _, err := os.Stat(filepath.Join(root, "presets-initialized")); !os.IsNotExist(err) {
		t.Fatal("unrecorded import seeded built-in profiles")
	}
	for _, operation := range []func() error{
		func() error { return store.SaveIfUnchangedContext(context.Background(), p) },
		func() error { return store.DeleteIfUnchangedContext(context.Background(), p.ID, p.UpdatedAt) },
	} {
		if err := operation(); !errors.Is(err, managed.ErrDenied) {
			t.Fatal("ordinary store call bypassed required audit", err)
		}
	}
	restore := filepath.Join(base, "restore")
	if err := profile.RestoreSnapshot(context.Background(), restore, []profile.Profile{p}, false, managed.NewGuard(nil)); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("unrecorded native-policy restore admitted", err)
	}
	if _, err := os.Lstat(restore); !os.IsNotExist(err) {
		t.Fatal("refused restore created its root")
	}
	directory := filepath.Join(base, "journal")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := captureAuditExecute(t, []string{"initialize", "--directory", directory})
	if err != nil {
		t.Fatal("ordinary native journal initialization failed", err)
	}
	initialized := decodeCheckpointObservations(t, data)
	if len(initialized) != 1 || initialized[0].Sequence != 0 || initialized[0].Producer.ActorClass != "user" {
		t.Fatal("ordinary-user audit genesis differs")
	}
	start := initialized[0]
	from, to := filepath.Join(base, "genesis.json"), filepath.Join(base, "head.json")
	writeRetainedCheckpoint(t, from, start)
	writeRetainedCheckpoint(t, to, start)
	command := []string{"import", "--directory", directory, "--from", from, "--to", to, "--profile", input}
	data, err = captureAuditExecute(t, command)
	if err != nil {
		t.Fatal("required-audit native CLI import failed", err)
	}
	observations := decodeCheckpointObservations(t, data)
	if len(observations) != 2 || observations[0].Sequence != 1 || observations[1].Sequence != 2 {
		t.Fatal("recorded native import did not publish intent and result")
	}
	saved, err := store.Get(p.ID)
	expected := p
	expected.UpdatedAt = saved.UpdatedAt
	if err != nil || saved.UpdatedAt.IsZero() || !reflect.DeepEqual(saved, expected) {
		t.Fatal("recorded native import content differs", err)
	}
	profiles, err = store.List()
	if err != nil || len(profiles) != 1 {
		t.Fatal("recorded native import created unexpected profiles", err)
	}
	profilePath := filepath.Join(root, "profiles", p.ID+".json")
	beforeProfile, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeJournal, err := os.ReadFile(filepath.Join(directory, "events.journal"))
	if err != nil {
		t.Fatal(err)
	}
	// The retained input is still genesis, so an unchanged retry must refuse
	// before another intent or profile write, preserving all previous bytes.
	retry, err := captureAuditExecute(t, command)
	if err == nil || len(retry) != 0 {
		t.Fatal("stale retained head was adopted or emitted output")
	}
	afterProfile, err := os.ReadFile(profilePath)
	if err != nil || !bytes.Equal(afterProfile, beforeProfile) {
		t.Fatal("stale-head refusal changed profile content")
	}
	afterJournal, err := os.ReadFile(filepath.Join(directory, "events.journal"))
	if err != nil || !bytes.Equal(afterJournal, beforeJournal) {
		t.Fatal("stale-head refusal changed journal bytes")
	}
	if err := store.DeleteIfUnchanged(saved.ID, saved.UpdatedAt); !errors.Is(err, managed.ErrDenied) {
		t.Fatal("ordinary delete reused implicit recorded authority", err)
	}
	writeRetainedCheckpoint(t, to, observations[1])
	exported, err := captureAuditExecute(t, []string{"export", "--directory", directory, "--from", from, "--to", to, "--consent", "metadata-only"})
	if err != nil {
		t.Fatal("native-policy journal export failed", err)
	}
	verified, err := audit.VerifySegment(context.Background(), bytes.NewReader(exported), start, observations[1])
	if err != nil || verified.Records != 2 {
		t.Fatal("native-policy recorded segment did not verify", err)
	}
	if bytes.Contains(exported, []byte(p.ID)) || bytes.Contains(exported, []byte(p.Name)) || bytes.Contains(exported, []byte(base)) {
		t.Fatal("profile/fixture data escaped native audit output")
	}
}

// Only the existing opted-in hosted root setup calls this source fixture. Its
// journal belongs to the administrator process, separate from the user stream.
func linuxRecordedPolicyUpdateProbe(t *testing.T, fixtureRoot string, envelope []byte) {
	t.Helper()
	linuxNativeContext(t)
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Fatal("recorded policy setup requires hosted root fixture")
	}
	directory := filepath.Join(fixtureRoot, "administrator-journal")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := captureAuditExecute(t, []string{"initialize", "--directory", directory})
	if err != nil {
		t.Fatal("administrator journal initialization", err)
	}
	initialized := decodeCheckpointObservations(t, data)
	if len(initialized) != 1 || initialized[0].Sequence != 0 || initialized[0].Producer.ActorClass != "administrator" {
		t.Fatal("administrator genesis differs")
	}
	start := initialized[0]
	from, to, input := filepath.Join(fixtureRoot, "administrator-genesis.json"), filepath.Join(fixtureRoot, "administrator-head.json"), filepath.Join(fixtureRoot, "administrator-update.json")
	writeRetainedCheckpoint(t, from, start)
	writeRetainedCheckpoint(t, to, start)
	if err := os.WriteFile(input, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	data, err = captureAuditExecute(t, []string{"policy-update", "--directory", directory, "--from", from, "--to", to, "--input", input})
	if err != nil {
		t.Fatal("recorded native policy update", err)
	}
	observations := decodeCheckpointObservations(t, data)
	if len(observations) != 2 || observations[0].Sequence != 1 || observations[1].Sequence != 2 {
		t.Fatal("administrator intent/result checkpoints differ")
	}
	writeRetainedCheckpoint(t, to, observations[1])
	exported, err := captureAuditExecute(t, []string{"export", "--directory", directory, "--from", from, "--to", to, "--consent", "metadata-only"})
	if err != nil {
		t.Fatal("administrator metadata export", err)
	}
	verified, err := audit.VerifySegment(context.Background(), bytes.NewReader(exported), start, observations[1])
	if err != nil || verified.Records != 2 {
		t.Fatal("administrator policy segment verification", err)
	}
	if bytes.Contains(exported, []byte(fixtureRoot)) || bytes.Contains(exported, envelope) {
		t.Fatal("administrator input escaped metadata")
	}
}
