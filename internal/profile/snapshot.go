package profile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/privatefile"
)

const MaxSnapshotProfiles = 256
const MaxSnapshotBytes = 8 << 20
const restoreMarker = ".restore-incomplete"
const restoreStage = ".restore-profiles"

var ErrRestoreIncomplete = errors.New("profile restore is incomplete; resume it with the authenticated backup before using this data directory")

func checkRestoreState(root string) error {
	_, err := os.Lstat(filepath.Join(root, restoreMarker))
	if err == nil {
		return ErrRestoreIncomplete
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func ValidateSnapshot(profiles []Profile) error {
	if len(profiles) > MaxSnapshotProfiles {
		return errors.New("snapshot exceeds 256 profiles")
	}
	seen := make(map[string]bool, len(profiles))
	size := 0
	for _, p := range profiles {
		if err := p.Validate(); err != nil {
			return err
		}
		if seen[p.ID] {
			return errors.New("snapshot contains duplicate profile IDs")
		}
		seen[p.ID] = true
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if len(data) > 1<<20 {
			return errors.New("snapshot profile exceeds 1 MiB")
		}
		formatted, err := json.MarshalIndent(p, "", "  ")
		if err != nil || len(formatted)+1 > 1<<20 {
			return errors.New("formatted snapshot profile exceeds 1 MiB")
		}
		size += len(data)
		if size > MaxSnapshotBytes {
			return errors.New("snapshot exceeds 8 MiB")
		}
	}
	return nil
}

// SnapshotContext takes one bounded, consistent read under the shared store
// lock. It never follows references to engine/configuration files.
func (s *Store) SnapshotContext(ctx context.Context) ([]Profile, error) {
	return snapshotContext(ctx, s, physicalSnapshotIO())
}

// restoreFiles canonicalizes the exact saved data, including revision stamps.
func restoreFiles(profiles []Profile) (map[string][]byte, []byte, error) {
	if err := ValidateSnapshot(profiles); err != nil {
		return nil, nil, err
	}
	ordered := append([]Profile{}, profiles...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	files := make(map[string][]byte, len(ordered))
	digest := sha256.New()
	for _, p := range ordered {
		data, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		if len(data)+1 > 1<<20 {
			return nil, nil, errors.New("formatted restored profile exceeds 1 MiB")
		}
		data = append(data, 10)
		files[p.ID+".json"] = data
		digest.Write(data)
	}
	marker := []byte("AccessWeaver profile restore v1\n" + hex.EncodeToString(digest.Sum(nil)) + "\n")
	return files, marker, nil
}

func writeRestoreFile(path string, data []byte) error {
	f, err := privatefile.Create(path)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return snapshotJoin(writeErr, f.Close())
}

func readRestoreFile(path string, limit int64) ([]byte, error) {
	return physicalSnapshotIO().readFile(context.Background(), path, limit)
}
func restoreDirectory(path string) ([]os.DirEntry, error) {
	return restoreDirectoryContext(context.Background(), path, physicalSnapshotIO())
}

// RestoreSnapshot publishes profiles only into an exclusively created root.
// Resume requires the exact authenticated snapshot marker and never replaces
// unrelated data. A retained marker blocks ordinary Store reads and mutations.
func RestoreSnapshot(ctx context.Context, root string, profiles []Profile, resume bool, guard *managed.Guard) error {
	return restoreSnapshotWithIO(ctx, root, profiles, resume, guard, physicalSnapshotIO())
}
func restoreSnapshotWithIO(ctx context.Context, root string, profiles []Profile, resume bool, guard *managed.Guard, ops snapshotIO) (failure error) {
	defer func() { failure = snapshotJoin(failure, ctx.Err()) }()
	files, marker, err := restoreFiles(profiles)
	if err != nil {
		return err
	}
	if err := guard.ProfileChanges(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("restore destination requires a canonical absolute path")
	}
	if !resume {
		if err := os.Mkdir(root, 0700); err != nil {
			return fmt.Errorf("restore requires a new data directory: %w", err)
		}
		if err := syncSnapshotDirectory(filepath.Dir(root)); err != nil {
			return err
		}
	}
	original, err := ops.named(root)
	if err != nil || original.Kind != fileidentity.Directory {
		return snapshotJoin(errors.New("restore root must be a real directory"), err)
	}
	controller, err := ops.acquire(ctx, filepath.Join(root, ".controller.lock"), true)
	if err != nil {
		return err
	}
	defer snapshotClose(ctx, ops, controller, &failure)
	lock, err := ops.acquire(ctx, filepath.Join(root, ".profiles.lock"), false)
	if err != nil {
		return err
	}
	defer snapshotClose(ctx, ops, lock, &failure)
	current, err := ops.named(root)
	if err != nil || !snapshotDirectoryBinding(original, current) {
		return snapshotJoin(errors.New("restore root changed"), err)
	}
	entries, err := restoreDirectoryContext(ctx, root, ops)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case ".controller.lock", ".profiles.lock", restoreMarker, "profiles", restoreStage, "presets-initialized":
		default:
			return errors.New("restore destination contains unrelated data; preserved without changes")
		}
	}
	markerPath := filepath.Join(root, restoreMarker)
	if resume {
		existing, err := ops.readFile(ctx, markerPath, 256)
		matches := bytes.Equal(existing, marker)
		clear(existing)
		if err != nil || !matches {
			return snapshotJoin(errors.New("restore marker does not match this authenticated snapshot"), err)
		}
	} else {
		if err := writeRestoreFile(markerPath, marker); err != nil {
			return err
		}
	}
	if err := syncSnapshotDirectory(root); err != nil {
		return err
	}
	if err := guard.ProfileChanges(); err != nil {
		return err
	}
	if err := restoreSnapshotFilesWithIO(ctx, root, files, guard, ops); err != nil {
		return err
	}
	presetPath := filepath.Join(root, "presets-initialized")
	if existing, err := ops.readFile(ctx, presetPath, 2); err == nil {
		matches := bytes.Equal(existing, []byte("1\n"))
		clear(existing)
		if !matches {
			return errors.New("unexpected preset initialization state")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := writeRestoreFile(presetPath, []byte("1\n")); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := guard.ProfileChanges(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syncSnapshotDirectory(root); err != nil {
		return err
	}
	// All data files are synced before this commit point. Full power-loss
	// durability of directory metadata still needs native qualification.
	if err := os.Remove(markerPath); err != nil {
		return err
	}
	return syncSnapshotDirectory(root)
}

func restoreSnapshotFiles(ctx context.Context, root string, files map[string][]byte, guard *managed.Guard) error {
	return restoreSnapshotFilesWithIO(ctx, root, files, guard, physicalSnapshotIO())
}
func restoreSnapshotFilesWithIO(ctx context.Context, root string, files map[string][]byte, guard *managed.Guard, ops snapshotIO) error {
	target := filepath.Join(root, "profiles")
	entries, err := restoreDirectoryContext(ctx, target, ops)
	if err == nil && len(entries) > 0 {
		// Process death after publication but before marker removal: accept
		// only the complete identical snapshot, without writing saved profiles.
		if len(entries) != len(files) {
			return errors.New("published restore contains unexpected profiles")
		}
		for _, entry := range entries {
			expected, ok := files[entry.Name()]
			if !ok {
				return errors.New("published restore contains unrelated files")
			}
			actual, err := ops.readFile(ctx, filepath.Join(target, entry.Name()), 1<<20)
			matches := bytes.Equal(actual, expected)
			clear(actual)
			if err != nil || !matches {
				return snapshotJoin(errors.New("published restore differs from authenticated snapshot"), err)
			}
		}
		if _, err := os.Lstat(filepath.Join(root, restoreStage)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("published restore retains unexpected staging state")
		}
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stage := filepath.Join(root, restoreStage)
	if err := os.Mkdir(stage, 0700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		entries, err := restoreDirectoryContext(ctx, stage, ops)
		if err != nil {
			return err
		}
		// Remove only known staged regular-file names. Never recurse, follow
		// links, truncate a hard link or delete an unexpected object.
		for _, entry := range entries {
			info, statErr := os.Lstat(filepath.Join(stage, entry.Name()))
			if _, ok := files[entry.Name()]; !ok || statErr != nil || !info.Mode().IsRegular() {
				return errors.New("unexpected restore staging object; preserved")
			}
		}
		for _, entry := range entries {
			if err := os.Remove(filepath.Join(stage, entry.Name())); err != nil {
				return err
			}
		}
	}
	for name, data := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := guard.ProfileChanges(); err != nil {
			return err
		}
		if err := writeRestoreFile(filepath.Join(stage, name), data); err != nil {
			return err
		}
	}
	if err := guard.ProfileChanges(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syncSnapshotDirectory(stage); err != nil {
		return err
	}
	// A concurrent constructor may have made an empty profiles directory before
	// noticing the marker. Nonrecursive removal fails if it contains any data.
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := replaceFile(stage, target); err != nil {
		return err
	}
	return syncSnapshotDirectory(root)
}
