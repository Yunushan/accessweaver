package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// Public-category joins here are synthetic, not native publication faults.
func TestAuditImportAtomicWriteCompletionMarkerPrecedesKnownRefusals(t *testing.T) {
	for _, known := range []error{profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied} {
		assertAuditImportReadCompletion(t, completeReviewedProfileImport(known, nil), "refused")
		joined := errors.Join(profile.ErrAtomicWriteUncertain, known, errors.New("PRIVATE_ATOMIC_CAUSE"))
		assertAuditImportReadCompletion(t, completeReviewedProfileImport(joined, nil), "indeterminate")
		wrapped := &os.PathError{Op: "rename", Path: "PRIVATE_ATOMIC_PATH", Err: joined}
		assertAuditImportReadCompletion(t, completeReviewedProfileImport(wrapped, nil), "indeterminate")
		allUncertain := errors.Join(joined, profile.ErrMutationUncertain, profile.ErrReadUnavailable)
		assertAuditImportReadCompletion(t, completeReviewedProfileImport(allUncertain, nil), "indeterminate")
	}
}

func TestAuditImportAtomicWriteCompletionActualPublicationFailureAndControllerClose(t *testing.T) {
	f := newAuditImportReadCompletionFixture(t)
	original := f.profileBytes(t)
	controller := f.controller(t)
	destination := filepath.Join(f.root, "owned-atomic-destination")
	if os.Mkdir(destination, 0700) != nil {
		f.preserve = true
		t.Fatal("owned atomic destination obstruction unavailable")
	}
	identity, err := fileidentity.FromPath(destination, false)
	if err != nil || identity.Kind != fileidentity.Directory {
		f.preserve = true
		t.Fatal("owned atomic destination identity unavailable")
	}
	payload := []byte("PRIVATE_ATOMIC_STAGED_INPUT\n")
	operationErr := profile.AtomicWrite(destination, payload)
	if !errors.Is(operationErr, profile.ErrAtomicWriteUncertain) || operationErr.Error() != profile.ErrAtomicWriteUncertain.Error() {
		f.preserve = true
		t.Fatal("actual atomic publication failure lost its private fixed category")
	}
	// A file-method PathError would be an unexpected earlier read/write/Close
	// failure, not the owned directory's intended later replace refusal.
	var earlierFailure *os.PathError
	if errors.As(operationErr, &earlierFailure) {
		f.preserve = true
		t.Fatal("actual atomic fixture encountered earlier source I/O uncertainty")
	}
	current, err := fileidentity.FromPath(destination, false)
	if err != nil || current.Kind != identity.Kind || current.ID != identity.ID {
		f.preserve = true
		t.Fatal("failed atomic publication replaced its destination directory")
	}
	children, err := os.ReadDir(destination)
	if err != nil || len(children) != 0 {
		f.preserve = true
		t.Fatal("failed atomic publication changed its destination directory")
	}
	entries, err := os.ReadDir(f.root)
	if err != nil {
		f.preserve = true
		t.Fatal("retained atomic stage inventory unavailable")
	}
	stage := ""
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".accessweaver-") {
			if stage != "" {
				f.preserve = true
				t.Fatal("unexpected additional atomic stages retained")
			}
			stage = filepath.Join(f.root, entry.Name())
		}
	}
	if stage == "" {
		f.preserve = true
		t.Fatal("actual failed publication stage was removed")
	}
	retained, err := fileinput.Read(context.Background(), stage, 4096)
	if err != nil || !bytes.Equal(retained, payload) {
		f.preserve = true
		t.Fatal("actual failed publication stage bytes unconfirmed")
	}
	actualClose := f.close(t, controller)
	if actualClose != nil {
		t.Fatal("actual controller Close failed before completion classification")
	}
	probe := f.controller(t)
	if f.close(t, probe) != nil {
		t.Fatal("independent controller acquisition Close unconfirmed")
	}
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(operationErr, actualClose), "indeterminate")
	for _, known := range []error{profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied} {
		// This error retains a real public AtomicWrite failure; only the
		// normally refused cofactor is synthetic. Classification grants no replay.
		joined := errors.Join(operationErr, known)
		if !errors.Is(joined, profile.ErrAtomicWriteUncertain) {
			t.Fatal("atomic category lost through a completion cofactor")
		}
		assertAuditImportReadCompletion(t, completeReviewedProfileImport(joined, actualClose), "indeterminate")
	}
	after, err := fileinput.Read(context.Background(), stage, 4096)
	if err != nil {
		f.preserve = true
		t.Fatal("retained atomic stage read unconfirmed")
	}
	if !bytes.Equal(after, payload) || !bytes.Equal(original, f.profileBytes(t)) {
		f.preserve = true
		t.Fatal("completion classification changed retained evidence")
	}
}
