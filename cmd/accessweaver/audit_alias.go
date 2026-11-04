package main

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
)

var errAuditOutputAlias = errors.New("audit outputs must be available, separate and independent of protected inputs")

// A binding retains metadata from the same open file used to read an input.
// Path validation alone cannot protect that object after its name is replaced.
type auditInputBinding struct {
	path  string
	state fileidentity.State
}

// References have an explicit leaf-link policy. Only genuine absence may omit
// an optional reference; metadata refusal must never make it optional.
type auditPathReference struct {
	path        string
	followLinks bool
	optional    bool
}

// checkAuditOutputAliases performs metadata queries only. It borrows output
// handles, never writes or closes them, and starts no worker that can outlive
// this call. Cancellation is cooperative around native metadata calls.
//
// Opaque nonnil writers remain the caller's forwarding responsibility. They do
// not waive validation of the source bindings and path references.
func checkAuditOutputAliases(ctx context.Context, outputs []io.Writer, bindings []auditInputBinding, refs []auditPathReference) error {
	if ctx == nil {
		return errAuditOutputAlias
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	var destinations []fileidentity.ID
	for _, writer := range outputs {
		if auditWriterUnavailable(writer) {
			return errAuditOutputAlias
		}
		file, direct := writer.(*os.File)
		if !direct {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := fileidentity.FromFile(file)
		if canceled := ctx.Err(); canceled != nil {
			return canceled
		}
		if err != nil {
			return errAuditOutputAlias
		}
		switch state.Kind {
		case fileidentity.Other:
			// Pipes and consoles have no regular-file destination to compare.
			continue
		case fileidentity.Regular:
		default:
			return errAuditOutputAlias
		}
		for _, previous := range destinations {
			if state.ID == previous {
				return errAuditOutputAlias
			}
		}
		// Compare every cached source identity before any fresh path query.
		// A replaced source name must not hide an alias to its old open object.
		for _, binding := range bindings {
			if state.ID == binding.state.ID {
				return errAuditOutputAlias
			}
		}
		destinations = append(destinations, state.ID)
	}

	for _, binding := range bindings {
		if binding.state.Kind != fileidentity.Regular {
			return errAuditOutputAlias
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := fileidentity.FromPath(binding.path, false)
		if canceled := ctx.Err(); canceled != nil {
			return canceled
		}
		if err != nil || current.Kind != fileidentity.Regular || current.ID != binding.state.ID || current.Size != binding.state.Size || !current.Modified.Equal(binding.state.Modified) {
			return errAuditOutputAlias
		}
	}

	var referenced []fileidentity.ID
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := fileidentity.FromPath(ref.path, ref.followLinks)
		if canceled := ctx.Err(); canceled != nil {
			return canceled
		}
		if err != nil {
			if ref.optional && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return errAuditOutputAlias
		}
		if state.Kind != fileidentity.Regular {
			return errAuditOutputAlias
		}
		referenced = append(referenced, state.ID)
	}
	for _, destination := range destinations {
		for _, source := range referenced {
			if destination == source {
				return errAuditOutputAlias
			}
		}
	}
	return ctx.Err()
}

func auditWriterUnavailable(writer io.Writer) bool {
	if writer == nil {
		return true
	}
	switch value := reflect.ValueOf(writer); value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}
