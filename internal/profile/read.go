package profile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/Yunushan/accessweaver/internal/fileinput"
)

// ErrReadUnavailable means a profile snapshot or its owned cleanup could not
// be confirmed. Its private causes remain inspectable with errors.Is/As.
var ErrReadUnavailable = errors.New("profile read or cleanup could not be confirmed")

type profileReadFailure struct{ cause error }

func (e *profileReadFailure) Error() string   { return ErrReadUnavailable.Error() }
func (e *profileReadFailure) Unwrap() []error { return []error{ErrReadUnavailable, e.cause} }

func profileReadUnavailable(cause error) error {
	return &profileReadFailure{cause: cause}
}

func profileReadCompletionError(bodyErr, closeErr error) error {
	if closeErr == nil {
		return bodyErr
	}
	if bodyErr == nil {
		return profileReadUnavailable(closeErr)
	}
	return profileReadUnavailable(errors.Join(bodyErr, closeErr))
}

// Install cleanup before the body, including on panic. Native I/O remains
// synchronous; cancellation does not abandon an owner or impose a hard timeout.
// A recovered body panic must not leave the profile lease held.
func readProfileSynchronously(ctx context.Context, read func(context.Context) (Profile, error), closeLease func() error) (p Profile, failure error) {
	defer func() {
		closeErr := closeLease()
		failure = profileReadCompletionError(failure, ctx.Err())
		failure = profileReadCompletionError(failure, closeErr)
		if failure != nil {
			p = Profile{}
		}
	}()
	p, failure = read(ctx)
	return
}

func (s *Store) getLockedContext(ctx context.Context, id string) (Profile, error) {
	return s.getLockedContextWithRead(ctx, id, fileinput.Read)
}

// The per-call composition tests genuine snapshot/lease operations without a
// global or user-selectable backend. Only the first Lstat can establish clean
// absence: after observing a regular file, even nested NotExist is uncertainty.
func (s *Store) getLockedContextWithRead(ctx context.Context, id string, snapshot func(context.Context, string, int64) ([]byte, error)) (p Profile, failure error) {
	// Cancellation during Lstat or decoding must not turn a partial semantic
	// error (or apparent absence) into permission for a later mutation.
	defer func() {
		failure = profileReadCompletionError(failure, ctx.Err())
		if failure != nil {
			p = Profile{}
		}
	}()
	if err := ctx.Err(); err != nil {
		return Profile{}, profileReadUnavailable(err)
	}
	file, err := s.filename(id)
	if err != nil {
		return Profile{}, err
	}
	info, err := os.Lstat(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Profile{}, err
		}
		return Profile{}, profileReadUnavailable(err)
	}
	if !info.Mode().IsRegular() {
		return Profile{}, profileReadUnavailable(errors.New("profile must be a regular file"))
	}
	data, err := snapshot(ctx, file, 1<<20)
	defer clear(data)
	if err != nil {
		return Profile{}, profileReadUnavailable(err)
	}
	if err := ctx.Err(); err != nil {
		return Profile{}, profileReadUnavailable(err)
	}
	p, err = Decode(bytes.NewReader(data))
	if err != nil {
		return Profile{}, fmt.Errorf("%s: %w", id, err)
	}
	if p.ID != id {
		return Profile{}, errors.New("profile id does not match filename")
	}
	if err := ctx.Err(); err != nil {
		return Profile{}, profileReadUnavailable(err)
	}
	return p, nil
}
