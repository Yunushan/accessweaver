package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

const (
	workflowLifecycleManifestEntries       = 8192
	workflowLifecycleManifestDepth         = 32
	workflowLifecycleManifestBytes         = 32 << 10
	workflowLifecycleManifestInput   int64 = 8 << 30
)

type workflowLifecycleArtifact struct {
	Path   string `json:"path"` // Exact relative filename bytes, base64; never client authority.
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}
type workflowLifecycleManifest struct {
	Classification  string `json:"classification"`
	Scope           string `json:"scope"`
	WorkdirPresent  bool   `json:"workdirPresent"`
	Count           uint64 `json:"count"`
	LogicalBytes    int64  `json:"logicalBytes"`
	HashBudgetBytes int64  `json:"hashBudgetBytes"`
	SHA256          string `json:"sha256,omitempty"`
	Protection      string `json:"protection"`
}

func unknownWorkflowLifecycleManifest() workflowLifecycleManifest {
	return workflowLifecycleManifest{Classification: "unknown", Scope: "local-workdir-only", HashBudgetBytes: workflowLifecycleManifestInput, Protection: "retirement-unavailable"}
}
func validWorkflowLifecycleManifest(manifest workflowLifecycleManifest) bool {
	if (manifest.Classification != "observed" && manifest.Classification != "unknown") || manifest.Scope != "local-workdir-only" || manifest.Protection != "retirement-unavailable" || manifest.HashBudgetBytes != workflowLifecycleManifestInput || manifest.Count > workflowLifecycleManifestEntries || manifest.LogicalBytes < 0 || manifest.LogicalBytes > workflowLifecycleManifestInput {
		return false
	}
	if manifest.Classification == "unknown" {
		return manifest.Count == 0 && manifest.LogicalBytes == 0 && !manifest.WorkdirPresent && manifest.SHA256 == ""
	}
	return historyHex(manifest.SHA256, 64) && (manifest.WorkdirPresent || manifest.Count == 0 && manifest.LogicalBytes == 0)
}

// Collection is a bounded observation, never a deletion/authorization catalog.
// Overflow, unreadable/special/reparse objects or namespace drift produce a
// CLOSED unknown/protected manifest, not a truncated apparently complete list.
// Only owned-handle Close errors are returned as local cleanup uncertainty.
func (m *Manager) collectWorkflowLifecycleManifest(id string) (manifest workflowLifecycleManifest, err error) {
	unknown := unknownWorkflowLifecycleManifest()
	manifest = unknown
	path := filepath.Join(m.root, id)
	named, cause := os.Lstat(path)
	if errors.Is(cause, os.ErrNotExist) {
		manifest.Classification = "observed"
		manifest.SHA256 = workflowLifecycleJSONHash([]workflowLifecycleArtifact{})
		return manifest, nil
	}
	if cause != nil || named.Mode()&os.ModeType != os.ModeDir {
		return unknown, nil
	}
	root, cause := os.OpenRoot(path)
	if cause != nil {
		return unknown, nil
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			manifest = unknown
			err = errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
		}
	}()
	opened, cause := root.Stat(".")
	if cause != nil || !opened.IsDir() || !os.SameFile(named, opened) {
		return unknown, nil
	}
	entries := []workflowLifecycleArtifact{}
	total := int64(0)
	add := func(entry workflowLifecycleArtifact) bool {
		if len(entries) >= workflowLifecycleManifestEntries {
			return false
		}
		entries = append(entries, entry)
		return true
	}
	var walk func(string, int) (bool, error)
	walk = func(relative string, depth int) (complete bool, err error) {
		if depth > workflowLifecycleManifestDepth || len(relative) > 1024 {
			return false, nil
		}
		before, cause := root.Lstat(relative)
		if cause != nil || before.Mode()&os.ModeType != os.ModeDir {
			return false, nil
		}
		dir, cause := root.Open(relative)
		if cause != nil {
			return false, nil
		}
		defer func() {
			if closeErr := dir.Close(); closeErr != nil {
				complete = false
				err = errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
			}
		}()
		held, cause := dir.Stat()
		if cause != nil || !held.IsDir() || !os.SameFile(before, held) {
			return false, nil
		}
		for {
			batch, readErr := dir.ReadDir(128)
			if readErr != nil && readErr != io.EOF {
				return false, nil
			}
			for _, child := range batch {
				leaf := child.Name()
				if filepath.Base(leaf) != leaf || leaf == "." || leaf == ".." {
					return false, nil
				}
				name := filepath.Join(relative, leaf)
				if len(name) > 1024 {
					return false, nil
				}
				info, cause := root.Lstat(name)
				if cause != nil {
					return false, nil
				}
				artifact := workflowLifecycleArtifact{Path: base64.StdEncoding.EncodeToString([]byte(name))}
				if info.Mode()&os.ModeType == os.ModeDir {
					artifact.Kind = "directory"
					if !add(artifact) {
						return false, nil
					}
					ok, walkErr := walk(name, depth+1)
					if !ok || walkErr != nil {
						return false, walkErr
					}
				} else if info.Mode().IsRegular() {
					if info.Size() < 0 || info.Size() > workflowLifecycleManifestInput-total {
						return false, nil
					}
					hash, count, ok, hashErr := hashWorkflowLifecycleArtifact(root, name, info, workflowLifecycleManifestInput-total)
					if !ok || hashErr != nil {
						return false, hashErr
					}
					total += count
					artifact.Kind = "file"
					artifact.Size = count
					artifact.SHA256 = hash
					if !add(artifact) {
						return false, nil
					}
				} else {
					return false, nil
				}
			}
			if readErr == io.EOF {
				break
			}
		}
		after, cause := dir.Stat()
		if cause != nil {
			return false, nil
		}
		current, cause := root.Lstat(relative)
		if cause != nil || !current.IsDir() || !os.SameFile(held, after) || !os.SameFile(after, current) || held.ModTime() != after.ModTime() {
			return false, nil
		}
		return true, nil
	}
	complete, walkErr := walk(".", 0)
	if !complete || walkErr != nil {
		return unknown, walkErr
	}
	after, cause := os.Lstat(path)
	if cause != nil || !after.IsDir() || !os.SameFile(named, after) {
		return unknown, nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return workflowLifecycleManifest{Classification: "observed", Scope: "local-workdir-only", WorkdirPresent: true, Count: uint64(len(entries)), LogicalBytes: total, HashBudgetBytes: workflowLifecycleManifestInput, SHA256: workflowLifecycleJSONHash(entries), Protection: "retirement-unavailable"}, nil
}

func hashWorkflowLifecycleArtifact(root *os.Root, name string, named os.FileInfo, remaining int64) (hash string, count int64, complete bool, err error) {
	file, cause := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if cause != nil {
		return "", 0, false, nil
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			complete = false
			err = errors.Join(err, workflowFailure(ErrWorkflowCleanup, closeErr))
		}
	}()
	before, cause := file.Stat()
	if cause != nil || !before.Mode().IsRegular() || !os.SameFile(named, before) {
		return "", 0, false, nil
	}
	digest := sha256.New()
	count, cause = io.CopyBuffer(digest, io.LimitReader(workflowContextReader{context.Background(), file}, remaining+1), make([]byte, 32<<10))
	if cause != nil || count > remaining {
		return "", count, false, nil
	}
	after, cause := file.Stat()
	if cause != nil {
		return "", count, false, nil
	}
	current, cause := root.Lstat(name)
	if cause != nil || !current.Mode().IsRegular() || !os.SameFile(before, after) || !os.SameFile(after, current) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || count != after.Size() {
		return "", count, false, nil
	}
	return hex.EncodeToString(digest.Sum(nil)), count, true, nil
}
