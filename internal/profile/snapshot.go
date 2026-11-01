package profile

import (
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

	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
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
	lock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	path := filepath.Join(s.Root, "profiles")
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !named.IsDir() || named.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("snapshot requires a real profile directory")
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(named, opened) {
		return nil, errors.New("snapshot directory changed during open")
	}
	result := make([]Profile, 0)
	scanned, size := 0, 0
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			scanned++
			if scanned > 4096 {
				return nil, errors.New("snapshot directory exceeds 4096 entries")
			}
			if filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			if len(result) >= MaxSnapshotProfiles {
				return nil, errors.New("snapshot exceeds 256 profiles")
			}
			p, err := s.getLocked(entry.Name()[:len(entry.Name())-5])
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(p)
			if err != nil {
				return nil, err
			}
			size += len(data)
			if size > MaxSnapshotBytes {
				return nil, errors.New("snapshot exceeds 8 MiB")
			}
			result = append(result, p)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
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
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close())
}

func readRestoreFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("unexpected restore file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("restore file changed during open")
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func restoreDirectory(path string) ([]os.DirEntry, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("restore requires real directories")
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(MaxSnapshotProfiles + 10)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > MaxSnapshotProfiles+5 {
		return nil, errors.New("unexpected restore directory contents")
	}
	return entries, nil
}

// RestoreSnapshot publishes profiles only into an exclusively created root.
// Resume requires the exact authenticated snapshot marker and never replaces
// unrelated data. A retained marker blocks ordinary Store reads and mutations.
func RestoreSnapshot(ctx context.Context, root string, profiles []Profile, resume bool, guard *managed.Guard) error {
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
	original, err := os.Lstat(root)
	if err != nil || !original.IsDir() || original.Mode()&os.ModeSymlink != 0 {
		return errors.New("restore root must be a real directory")
	}
	controller, err := filelock.TryAcquire(filepath.Join(root, ".controller.lock"))
	if err != nil {
		return err
	}
	defer controller.Close()
	lock, err := filelock.Acquire(ctx, filepath.Join(root, ".profiles.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := os.Lstat(root)
	if err != nil || !os.SameFile(original, current) {
		return errors.New("restore root changed")
	}
	entries, err := restoreDirectory(root)
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
		existing, err := readRestoreFile(markerPath, 256)
		if err != nil || string(existing) != string(marker) {
			return errors.New("restore marker does not match this authenticated snapshot")
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
	if err := restoreSnapshotFiles(ctx, root, files, guard); err != nil {
		return err
	}
	presetPath := filepath.Join(root, "presets-initialized")
	if existing, err := readRestoreFile(presetPath, 2); err == nil {
		if string(existing) != "1\n" {
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
	target := filepath.Join(root, "profiles")
	entries, err := restoreDirectory(target)
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
			actual, err := readRestoreFile(filepath.Join(target, entry.Name()), 1<<20)
			if err != nil || string(actual) != string(expected) {
				return errors.New("published restore differs from authenticated snapshot")
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
		entries, err := restoreDirectory(stage)
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
