package main

import (
	"errors"
	"io"
	"os"

	"github.com/Yunushan/accessweaver/internal/profile"
)

var errOrdinaryProfileInput = errors.New("profile input could not be confirmed")
var errOrdinaryCommandCleanup = errors.New("command cleanup could not be confirmed; do not repeat automatically")
var errOrdinaryValidationOutput = errors.New("profile validation output could not be completed")
var errOrdinaryImportOutput = errors.New("profile import completed but its output could not be written; do not repeat automatically")

type ordinaryCommandFailure struct {
	category error
	cause    error
}

func (e *ordinaryCommandFailure) Error() string   { return e.category.Error() }
func (e *ordinaryCommandFailure) Unwrap() []error { return []error{e.category, e.cause} }

// Retain body and close causes, and finish the synchronous owner before the
// command's enclosing runtime/controller scope can return. No retry or rollback.
func closeOrdinaryCommandOwner(body error, owner io.Closer) error {
	if err := owner.Close(); err != nil {
		return &ordinaryCommandFailure{category: errOrdinaryCommandCleanup, cause: errors.Join(body, err)}
	}
	return body
}

type ordinaryProfileReader struct {
	reader  io.Reader
	failure error
}

func (r *ordinaryProfileReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	// Only exact EOF is clean. An EOF co-cause must not erase an I/O failure.
	if err != nil && err != io.EOF {
		r.failure = errors.Join(r.failure, err)
	}
	return n, err
}

func decodeOwnedOrdinaryProfile(input io.ReadCloser) (p profile.Profile, failure error) {
	reader := &ordinaryProfileReader{reader: input}
	defer func() {
		closeErr := input.Close()
		if reader.failure != nil || closeErr != nil {
			p = profile.Profile{}
			failure = &ordinaryCommandFailure{category: errOrdinaryProfileInput, cause: errors.Join(failure, reader.failure, closeErr)}
		} else if failure != nil {
			p = profile.Profile{}
		}
	}()
	return profile.Decode(reader)
}

// Follow the same relative names, aliases and platform sharing as the legacy
// commands. Decode retains its actual 1MiB+1 read bound and schema policy.
func readOrdinaryProfile(source string) (profile.Profile, error) {
	file, err := os.Open(source)
	if err != nil {
		return profile.Profile{}, &ordinaryCommandFailure{category: errOrdinaryProfileInput, cause: err}
	}
	return decodeOwnedOrdinaryProfile(file)
}

// Production supplies the physical reader and (for import) store.Save. These
// per-call seams are private; there is no runtime/environment backend selector.
// Existing startup seeding and signal behavior remain in execute. A completed
// save is never reversed because acknowledgement/output subsequently fails.
func ordinaryProfileCommand(source string, out io.Writer, load func(string) (profile.Profile, error), save func(profile.Profile) error) error {
	p, err := load(source)
	if err != nil {
		return err
	}
	prefix, category := "Valid profile:", errOrdinaryValidationOutput
	if save != nil {
		if err := save(p); err != nil {
			return err
		}
		prefix, category = "Imported:", errOrdinaryImportOutput
	}
	message := prefix + " " + p.ID + "\n"
	n, err := io.WriteString(out, message)
	if n != len(message) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	if err != nil {
		return &ordinaryCommandFailure{category: category, cause: err}
	}
	return nil
}
