package workflow

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const (
	maxHistoryDirectoryEntries = 4096
	maxHistoryTotalBytes       = 64 << 20
)

// History fails explicitly when a listing exceeds its aggregate resource limits.
// It never deletes retained jobs, work directories or recovery evidence.
func (m *Manager) History() ([]Job, error) {
	return m.history(maxHistoryDirectoryEntries, maxHistoryTotalBytes)
}

// Smaller limits let tests exercise exact aggregate boundaries with small files.
func (m *Manager) history(maxEntries int, maxBytes int64) ([]Job, error) {
	directory, err := os.Open(m.root)
	if os.IsNotExist(err) {
		return []Job{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	// ReadDir without a count allocates the entire directory before any limit
	// can be checked. Include ignored entries in this bound as well.
	files := []os.DirEntry{}
	for {
		batch, err := directory.ReadDir(128)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if len(batch) > maxEntries-len(files) {
			return nil, fmt.Errorf("workflow history exceeds %d directory entries; all records retained", maxEntries)
		}
		files = append(files, batch...)
		if err == io.EOF {
			break
		}
	}
	// Preserve the filename order previously supplied by os.ReadDir.
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
	m.mu.Lock()
	activeID := m.job.ID
	m.mu.Unlock()
	out := []Job{}
	remaining := maxBytes
	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
			continue
		}
		// Charge every byte read, including malformed records. The streaming
		// guard also applies if the file grows after its size was checked.
		b, err := readWorkflowFile(filepath.Join(m.root, f.Name()), min(int64(maxHistoryRecordBytes), remaining))
		if err != nil {
			return nil, fmt.Errorf("read workflow history (total listing limit %d bytes; all records retained): %w", maxBytes, err)
		}
		remaining -= int64(len(b))
		var j Job
		if json.Unmarshal(b, &j) == nil {
			if j.State == "running" && j.ID != activeID {
				j.State = "interrupted"
				j.Error = "Controller stopped before outcome was recorded; inspect the Windows recovery journal"
			}
			out = append(out, j)
		}
	}
	return out, nil
}
