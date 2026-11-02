package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	maxResultBytes        = 32 << 20
	maxJobErrorBytes      = 16 << 10
	maxHistoryRecordBytes = 64 << 20
)

func validateResult(result json.RawMessage) error {
	if len(result) > maxResultBytes {
		return errors.New("workflow result exceeds 32 MiB; inspect process.log and the recovery journal")
	}
	// A failed tool may have no result. The executor's error remains authoritative.
	if len(result) != 0 {
		// A result is embedded one level inside its Job. It must remain valid at
		// that depth too, rather than producing a record the reader cannot decode.
		wrapped := make([]byte, 0, len(result)+2)
		wrapped = append(wrapped, '[')
		wrapped = append(wrapped, result...)
		wrapped = append(wrapped, ']')
		if !json.Valid(result) || !json.Valid(wrapped) {
			return errors.New("workflow returned invalid result JSON; inspect process.log and the recovery journal")
		}
	}
	return nil
}

// Keep the result as compact JSON in this private data file. Indentation, HTML
// escaping and even Encoder.SetEscapeHTML(false)'s Unicode-separator escaping
// can expand a valid result beyond the reader's limit. Private metadata strings
// use bounded JSON quoting; timestamps retain standard encoding. Untrusted
// result bytes are validated and compacted.
// These records must never be embedded directly in HTML or JavaScript.
func encodeJob(job Job) ([]byte, error) {
	// The complete encoded record is validated below before persistence.
	prepared, err := prepareJobOutput(job, 0)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err := prepared.writeTo(&buffer); err != nil {
		return nil, err
	}
	encoded := buffer.Bytes()
	if len(encoded) > maxHistoryRecordBytes {
		return nil, errors.New("serialized workflow job exceeds the history record limit")
	}
	if !json.Valid(encoded) {
		return nil, errors.New("serialized workflow job is not valid JSON")
	}
	return encoded, nil
}

func boundedJobError(message string) string {
	if len(message) <= maxJobErrorBytes {
		return strings.ToValidUTF8(message, "?")
	}
	const notice = "\n[Error truncated; inspect process.log, any retained result and recovery journal.]"
	end := maxJobErrorBytes - len(notice)
	for end > 0 && !utf8.RuneStart(message[end]) {
		end--
	}
	return strings.ToValidUTF8(message[:end], "?") + notice
}

// Bound reads even if a file grows after Stat. Do not follow a named symlink or
// accept a pipe/device in place of a result or persisted job record.
func readWorkflowFile(path string, limit int64) ([]byte, error) {
	return readWorkflowFileContext(context.Background(), path, limit)
}

func readWorkflowFileContext(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	return readBoundedContext(ctx, f, limit)
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	return readBoundedContext(context.Background(), r, limit)
}

func readBoundedContext(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(workflowContextReader{ctx, r}, limit+1))
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("workflow record exceeds %d bytes", limit)
	}
	return b, nil
}

// Limit each underlying read so a large record still reaches cancellation
// checkpoints. This cannot interrupt a filesystem operation already in progress.
type workflowContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r workflowContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 32<<10 {
		p = p[:32<<10]
	}
	return r.reader.Read(p)
}
