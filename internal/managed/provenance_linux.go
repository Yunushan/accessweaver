//go:build linux && (amd64 || arm64)

package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/linuxtrust"
)

func checkProtectedInput(path, digest string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("managed inputs require a canonical absolute local path")
	}
	parent, err := linuxtrust.OpenRootDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("untrusted managed parent: %w", err)
	}
	defer parent.Close()
	var input *os.File
	if directory {
		input, err = linuxtrust.OpenDirectoryAt(parent, filepath.Base(path), 0)
	} else {
		input, err = linuxtrust.OpenRegularAt(parent, filepath.Base(path), 0)
	}
	if err != nil {
		return err
	}
	defer input.Close()
	root := parent
	if directory {
		root = input
	}
	count := 0
	if err := checkLinuxInputTree(root, 0, &count); err != nil {
		return err
	}
	if directory {
		if digest != "" {
			return errors.New("directory contents cannot use a file digest")
		}
		return nil
	}
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0111 != 0 {
		var magic [4]byte
		if _, err := input.ReadAt(magic[:], 0); err != nil || magic != [4]byte{0x7f, 'E', 'L', 'F'} {
			return errors.New("managed executable inputs require an ELF file; interpreter assets are not yet qualified")
		}
	}
	if digest == "" {
		return nil
	}
	if !digestPattern.MatchString(digest) {
		return errors.New("managed file requires a SHA-256 digest")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(input, (512<<20)+1))
	if err != nil {
		return err
	}
	if size > 512<<20 {
		return errors.New("managed input exceeds 512 MiB")
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("managed input SHA-256 mismatch")
	}
	return nil
}
func checkLinuxInputTree(dir *os.File, depth int, count *int) error {
	if depth > 32 {
		return errors.New("managed input directory exceeds 32 levels")
	}
	// Each directory is opened independently; enumeration offsets never mutate
	// the caller's descriptor or another concurrent check.
	fd, err := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	current := os.NewFile(uintptr(fd), dir.Name())
	if _, err := linuxtrust.Check(current, true, 0); err != nil {
		current.Close()
		return err
	}
	defer current.Close()
	for {
		entries, readErr := current.ReadDir(128)
		for _, entry := range entries {
			*count++
			if *count > 4096 {
				return errors.New("managed input directory exceeds 4096 entries")
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("managed input directory contains a symlink")
			}
			var child *os.File
			if entry.IsDir() {
				child, err = linuxtrust.OpenDirectoryAt(dir, entry.Name(), 0)
			} else {
				child, err = linuxtrust.OpenRegularAt(dir, entry.Name(), 0)
			}
			if err != nil {
				return err
			}
			if entry.IsDir() {
				err = checkLinuxInputTree(child, depth+1, count)
			}
			closeErr := child.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
