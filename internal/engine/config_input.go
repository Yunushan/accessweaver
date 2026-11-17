package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const configInputLimit = 4 << 20

var errConfigInputUnavailable = errors.New("configuration read could not be confirmed")
var errConfigInputSize = errors.New("configuration must be a regular file no larger than 4 MiB")
var errConfigInputChanged = errors.New("configuration changed while being read")

type configInputFailure struct{ cause error }

func (e *configInputFailure) Error() string   { return errConfigInputUnavailable.Error() }
func (e *configInputFailure) Unwrap() []error { return []error{errConfigInputUnavailable, e.cause} }

type configInputFile interface {
	io.ReadCloser
	Stat() (os.FileInfo, error)
}

// Preserve followed local aliases. Windows acquisition refuses remote namespaces
// before native file access; other platforms retain their existing semantics.
// The preliminary Stat is advisory; only the acquired reader supplies bytes.
// This is a bounded observed stream, not an immutable snapshot or a binding to
// an external engine's later reopen of an original configuration pathname.
func readConfigInput(path string) ([]byte, error) {
	return readConfigInputContext(context.Background(), path)
}

func readConfigInputContext(ctx context.Context, path string) ([]byte, error) {
	if err := preparationContextError(ctx); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("configPath must be an absolute path to a local file")
	}
	info, err := statPreviewInput(path)
	if err != nil {
		return nil, &configInputFailure{cause: errors.Join(err, preparationContextError(ctx))}
	}
	if !info.regular || info.size > configInputLimit {
		return nil, errConfigInputSize
	}
	if err := preparationContextError(ctx); err != nil {
		return nil, err
	}
	file, err := openConfigInput(path)
	if err != nil {
		return nil, &configInputFailure{cause: errors.Join(err, preparationContextError(ctx))}
	}
	return readOwnedConfigInputContext(ctx, file)
}

// Take ownership immediately, and release no bytes until Close is confirmed.
func readOwnedConfigInput(file configInputFile) ([]byte, error) {
	return readOwnedConfigInputContext(context.Background(), file)
}

func readOwnedConfigInputContext(ctx context.Context, file configInputFile) (data []byte, failure error) {
	defer func() {
		closeErr := file.Close()
		if canceled := preparationContextError(ctx); failure != nil || closeErr != nil || canceled != nil {
			data = nil
			failure = &configInputFailure{cause: errors.Join(failure, closeErr, canceled)}
		}
	}()
	if err := preparationContextError(ctx); err != nil {
		return nil, err
	}
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > configInputLimit {
		return nil, errConfigInputSize
	}
	data, err = io.ReadAll(io.LimitReader(preparationReader{ctx: ctx, reader: file}, configInputLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > configInputLimit {
		return nil, errConfigInputSize
	}
	if err := preparationContextError(ctx); err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || before.Size() != after.Size() || int64(len(data)) != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errConfigInputChanged
	}
	return data, nil
}

func inspectConfigBytes(engine string, data []byte) error {
	if engine != "wiresock" {
		return nil
	}
	// Preserve Scanner's line limit and existing hook key rules. No line or
	// configuration value is included in a diagnostic.
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		key, _, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "preup", "postup", "predown", "postdown":
			return errors.New("WireSock configuration contains a command hook (PreUp/PostUp/PreDown/PostDown); remove hooks for managed mode")
		}
	}
	if scanner.Err() != nil {
		return errors.New("could not inspect WireSock configuration")
	}
	return nil
}
