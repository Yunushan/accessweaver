package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Store struct {
	Root string
	mu   sync.Mutex
}

func DefaultRoot() (string, error) {
	p, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(p, "AccessWeaver"), nil
}
func NewStore(root string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(root, "profiles"), 0700); err != nil {
		return nil, err
	}
	return &Store{Root: root}, nil
}
func (s *Store) filename(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", errors.New("invalid profile ID")
	}
	return filepath.Join(s.Root, "profiles", id+".json"), nil
}

func (s *Store) Get(id string) (Profile, error) {
	file, err := s.filename(id)
	if err != nil {
		return Profile{}, err
	}
	info, err := os.Lstat(file)
	if err != nil {
		return Profile{}, err
	}
	if !info.Mode().IsRegular() {
		return Profile{}, errors.New("profile must be a regular file")
	}
	f, err := os.Open(file)
	if err != nil {
		return Profile{}, err
	}
	defer f.Close()
	p, err := Decode(f)
	if err != nil {
		return Profile{}, fmt.Errorf("%s: %w", id, err)
	}
	if p.ID != id {
		return Profile{}, errors.New("profile id does not match filename")
	}
	return p, nil
}
func (s *Store) List() ([]Profile, error) {
	dir := filepath.Join(s.Root, "profiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(entries))
	for _, f := range entries {
		if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
			continue
		}
		id := f.Name()[:len(f.Name())-5]
		p, err := s.Get(id)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (s *Store) Save(p Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path, err := s.filename(p.ID)
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return errors.New("refusing to overwrite non-regular file")
	}
	return AtomicWrite(path, b)
}
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := s.filename(id)
	if err != nil {
		return err
	}
	return os.Remove(file)
}

func AtomicWrite(file string, data []byte) error {
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".accessweaver-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// Atomic replace is platform-specific; Win32 MoveFileExW handles existing files.
	if err = replaceFile(temp, file); err != nil {
		return err
	}
	return nil
}
func (s *Store) Seed(samples []Profile) error {
	// Seeding is first-run initialization, not synchronization. Once the user
	// deletes a bundled profile it must stay deleted on subsequent launches.
	marker := filepath.Join(s.Root, "presets-initialized")
	if info, err := os.Lstat(marker); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("preset initialization marker must be a regular file")
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, p := range samples {
		f, err := s.filename(p.ID)
		if err != nil {
			return err
		}
		_, err = os.Stat(f)
		if err == nil {
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := s.Save(p); err != nil {
			return err
		}
	}
	return AtomicWrite(marker, []byte("1\n"))
}
