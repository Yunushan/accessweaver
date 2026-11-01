package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	maxResultBytes        = 32 << 20
	maxHistoryRecordBytes = 64 << 20
)

func validateResult(result json.RawMessage) error {
	if len(result) > maxResultBytes {
		return errors.New("workflow result exceeds 32 MiB; inspect process.log and the recovery journal")
	}
	// A failed tool may have no result. The executor's error remains authoritative.
	if len(result) != 0 && !json.Valid(result) {
		return errors.New("workflow returned invalid result JSON; inspect process.log and the recovery journal")
	}
	return nil
}

// Bound reads even if a file grows after Stat. Do not follow a named symlink or
// accept a pipe/device in place of a result or persisted job record.
func readWorkflowFile(path string, limit int64) ([]byte, error) {
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !named.Mode().IsRegular() {
		return nil, errors.New("workflow record must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(named, opened) {
		return nil, errors.New("workflow record changed while opening")
	}
	if opened.Size() > limit {
		return nil, fmt.Errorf("workflow record exceeds %d bytes", limit)
	}
	return readBounded(f, limit)
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("workflow record exceeds %d bytes", limit)
	}
	return b, nil
}
