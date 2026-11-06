package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/backup"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

const backupUsage = `Encrypted saved-profile backup (no engines or OS state):
  accessweaver backup create --out FILE --passphrase-file PRIVATE_FILE
  accessweaver backup inspect --archive FILE --passphrase-file PRIVATE_FILE
  accessweaver backup restore --archive FILE --passphrase-file PRIVATE_FILE --into ABSOLUTE_NEW_DIRECTORY [--resume]
Keep the passphrase file separate from the archive. Existing destinations are refused.
See docs/BACKUP_RESTORE.md for recovery and privacy limits.
`

func backupCommand(args []string, root string) error {
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signals, time.Minute)
	defer cancel()
	return backupCommandContext(ctx, args, root)
}

func backupCommandContext(ctx context.Context, args []string, root string) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Print(backupUsage)
		return nil
	}
	if len(args) == 0 {
		return errors.New("usage: accessweaver backup create|inspect|restore [options]")
	}
	action := args[0]
	if action != "create" && action != "inspect" && action != "restore" {
		return errors.New("unknown backup operation")
	}
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	passwordFile := flags.String("passphrase-file", "", "private UTF-8 passphrase file")
	archive := flags.String("archive", "", "encrypted backup archive")
	out := flags.String("out", "", "new encrypted backup output file")
	into := flags.String("into", "", "new absolute data directory")
	resume := flags.Bool("resume", false, "resume the same interrupted restore")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(backupUsage)
			return nil
		}
		return errors.New("invalid backup options; use backup create --out FILE --passphrase-file FILE, or backup inspect|restore --archive FILE --passphrase-file FILE [--into NEW_DIRECTORY] [--resume]")
	}
	if flags.NArg() != 0 || *passwordFile == "" {
		return errors.New("backup requires --passphrase-file and named options only")
	}
	if action == "create" && (*out == "" || *archive != "" || *into != "" || *resume) {
		return errors.New("backup create requires --out; archive/into/resume are not applicable")
	}
	if action == "inspect" && (*archive == "" || *out != "" || *into != "" || *resume) {
		return errors.New("backup inspect requires --archive only")
	}
	if action == "restore" && (*archive == "" || *into == "" || *out != "") {
		return errors.New("backup restore requires --archive and --into")
	}
	if action == "restore" {
		if err := managed.NewGuard(nil).ProfileChanges(); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return backupFailure("backup operation canceled", err)
	}
	passwordBytes, err := fileinput.Read(ctx, *passwordFile, 1026)
	if err != nil {
		return backupFailure("backup passphrase input failed", err)
	}
	defer clear(passwordBytes)
	// Remove exactly one conventional file line ending. Never trim spaces,
	// normalize Unicode, or include the passphrase in a diagnostic.
	password := passwordBytes
	if len(password) > 0 && password[len(password)-1] == 10 {
		password = password[:len(password)-1]
		if len(password) > 0 && password[len(password)-1] == 13 {
			password = password[:len(password)-1]
		}
	}
	if !utf8.Valid(password) || len(password) < 12 || len(password) > 1024 {
		return errors.New("backup passphrase must contain 12-1024 UTF-8 bytes")
	}
	if action == "create" {
		// A nonexistent source must not create or seed application state.
		info, err := os.Stat(filepath.Join(root, "profiles"))
		if err != nil || !info.IsDir() {
			return errors.New("backup source has no existing profile directory")
		}
		destination, err := prepareBackupOutput(ctx, *out, root)
		if err != nil {
			return err
		}
		// The held output parent is retained through crypto and all output I/O.
		defer destination.Close()
		store, err := profile.NewStore(root)
		if err != nil {
			return backupFailure("backup source snapshot failed", errors.Join(err, destination.Close(), ctx.Err()))
		}
		profiles, err := store.SnapshotContext(ctx)
		if err != nil {
			return backupFailure("backup source snapshot failed", errors.Join(err, destination.Close(), ctx.Err()))
		}
		if err = ctx.Err(); err != nil {
			return backupFailure("backup operation canceled", errors.Join(err, destination.Close(), ctx.Err()))
		}
		data, err := backup.Encrypt(profiles, string(password), time.Now())
		if err != nil {
			return backupFailure("backup encryption failed", errors.Join(err, destination.Close(), ctx.Err()))
		}
		if err = ctx.Err(); err != nil {
			clear(data)
			return backupFailure("backup operation canceled", errors.Join(err, destination.Close(), ctx.Err()))
		}
		err = destination.Write(ctx, data)
		clear(data)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"operation": "backup-create", "schemaVersion": 1, "profiles": len(profiles), "encrypted": true, "externalFilesIncluded": false})
	}
	data, err := fileinput.Read(ctx, *archive, backup.MaxArchiveBytes)
	if err != nil {
		return backupFailure("backup archive input failed", err)
	}
	defer clear(data)
	if err = ctx.Err(); err != nil {
		return backupFailure("backup operation canceled", err)
	}
	snapshot, err := backup.Decrypt(data, string(password))
	if err != nil {
		if errors.Is(err, backup.ErrAuthentication) {
			return backupFailure(backup.ErrAuthentication.Error(), errors.Join(err, ctx.Err()))
		}
		return backupFailure("backup archive validation failed", errors.Join(err, ctx.Err()))
	}
	if err = ctx.Err(); err != nil {
		return backupFailure("backup operation canceled", err)
	}
	if action == "inspect" {
		return printJSON(map[string]any{"operation": "backup-inspect", "schemaVersion": 1, "createdAt": snapshot.CreatedAt, "profiles": len(snapshot.Profiles), "authenticated": true, "externalFilesIncluded": false})
	}
	if err := profile.RestoreSnapshot(ctx, *into, snapshot.Profiles, *resume, managed.NewGuard(nil)); err != nil {
		return backupFailure("backup restore failed; preserve the destination for inspection", err)
	}
	if err = ctx.Err(); err != nil {
		return backupFailure("backup operation canceled", err)
	}
	return printJSON(map[string]any{"operation": "backup-restore", "profiles": len(snapshot.Profiles), "complete": true, "startedEngines": false, "machinePolicyRestored": false})
}
