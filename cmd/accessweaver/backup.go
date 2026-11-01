package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/accessweaver/internal/backup"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func readBackupInput(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("backup input must be a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, errors.New("backup input changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("backup input exceeds size limit")
	}
	return data, nil
}

const backupUsage = `Encrypted saved-profile backup (no engines or OS state):
  accessweaver backup create --out FILE --passphrase-file PRIVATE_FILE
  accessweaver backup inspect --archive FILE --passphrase-file PRIVATE_FILE
  accessweaver backup restore --archive FILE --passphrase-file PRIVATE_FILE --into ABSOLUTE_NEW_DIRECTORY [--resume]
Keep the passphrase file separate from the archive. Existing destinations are refused.
See docs/BACKUP_RESTORE.md for recovery and privacy limits.
`

func backupCommand(args []string, root string) error {
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
	passwordBytes, err := readBackupInput(*passwordFile, 1026)
	if err != nil {
		return fmt.Errorf("read passphrase file: %w", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if action == "create" {
		// A nonexistent source must not create or seed application state.
		info, err := os.Stat(filepath.Join(root, "profiles"))
		if err != nil || !info.IsDir() {
			return errors.New("backup source has no existing profile directory")
		}
		output, err := filepath.Abs(*out)
		if err != nil {
			return err
		}
		sourceRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return err
		}
		outputParent, err := filepath.EvalSymlinks(filepath.Dir(output))
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(sourceRoot, filepath.Join(outputParent, filepath.Base(output)))
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return errors.New("backup output must be outside the source data directory")
		}
		store, err := profile.NewStore(root)
		if err != nil {
			return err
		}
		profiles, err := store.SnapshotContext(ctx)
		if err != nil {
			return err
		}
		data, err := backup.Encrypt(profiles, string(password), time.Now())
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("backup output requires a new file: %w", err)
		}
		_, writeErr := f.Write(data)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		if err := errors.Join(writeErr, f.Close()); err != nil {
			return fmt.Errorf("backup output incomplete; preserve for inspection and do not distribute: %w", err)
		}
		return printJSON(map[string]any{"operation": "backup-create", "schemaVersion": 1, "profiles": len(profiles), "encrypted": true, "externalFilesIncluded": false})
	}
	data, err := readBackupInput(*archive, backup.MaxArchiveBytes)
	if err != nil {
		return err
	}
	snapshot, err := backup.Decrypt(data, string(password))
	if err != nil {
		return err
	}
	if action == "inspect" {
		return printJSON(map[string]any{"operation": "backup-inspect", "schemaVersion": 1, "createdAt": snapshot.CreatedAt, "profiles": len(snapshot.Profiles), "authenticated": true, "externalFilesIncluded": false})
	}
	if err := profile.RestoreSnapshot(ctx, *into, snapshot.Profiles, *resume, managed.NewGuard(nil)); err != nil {
		return err
	}
	return printJSON(map[string]any{"operation": "backup-restore", "profiles": len(snapshot.Profiles), "complete": true, "startedEngines": false, "machinePolicyRestored": false})
}
