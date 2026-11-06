package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// These joins exercise public category priority, not injected native failures.
func TestAuditImportMutationCompletionMarkerPrecedesKnownRefusals(t *testing.T) {
	for _, known := range []struct {
		name  string
		cause error
	}{
		{"conflict", profile.ErrConflict}, {"busy", profile.ErrStoreBusy}, {"policy-denied", managed.ErrDenied},
	} {
		t.Run(known.name, func(t *testing.T) {
			assertAuditImportReadCompletion(t, completeReviewedProfileImport(known.cause, nil), "refused")
			mutation := errors.Join(profile.ErrMutationUncertain, known.cause)
			assertAuditImportReadCompletion(t, completeReviewedProfileImport(mutation, nil), "indeterminate")
			cofailures := errors.Join(mutation, profile.ErrReadUnavailable, filelock.ErrCloseUncertain, errors.New("PRIVATE_MUTATION_CAUSE"))
			assertAuditImportReadCompletion(t, completeReviewedProfileImport(cofailures, nil), "indeterminate")
			wrapped := &os.PathError{Op: "write", Path: "PRIVATE_MUTATION_PATH", Err: cofailures}
			assertAuditImportReadCompletion(t, completeReviewedProfileImport(wrapped, nil), "indeterminate")
			assertAuditImportReadCompletion(t, completeReviewedProfileImport(mutation, errors.New("PRIVATE_CONTROLLER_CLOSE")), "indeterminate")
		})
	}
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(nil, nil), "completed")
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(profile.ErrMutationUncertain, nil), "indeterminate")
}

func TestAuditImportMutationCompletionActualPublicationAndControllerClose(t *testing.T) {
	f := newAuditImportReadCompletionFixture(t)
	before := f.profileBytes(t)
	controller := f.controller(t)
	draft := f.current.Copy()
	draft.Name = "PRIVATE_PUBLISHED_MUTATION"
	operationErr := f.store.SaveIfUnchangedContext(context.Background(), draft)
	if operationErr != nil {
		f.preserve = true
		t.Fatal("actual optimistic publication unconfirmed")
	}
	published, err := f.store.GetContext(context.Background(), draft.ID)
	if err != nil {
		f.preserve = true
		t.Fatal("actual published profile read unconfirmed")
	}
	if published.ID != draft.ID || published.Name != draft.Name || published.UpdatedAt.IsZero() {
		t.Fatal("actual optimistic publication not observed")
	}
	after := f.profileBytes(t)
	if bytes.Equal(before, after) {
		t.Fatal("actual optimistic publication did not change profile bytes")
	}
	actualClose := f.close(t, controller)
	if actualClose != nil {
		t.Fatal("actual controller Close failed before classification")
	}
	probe := f.controller(t)
	if f.close(t, probe) != nil {
		t.Fatal("independent controller Close unconfirmed")
	}
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(operationErr, actualClose), "completed")
	// Publication and physical controller release above are real. Only this
	// reported mutation/read/refusal cofailure is synthetic; it authorizes no replay.
	reported := errors.Join(profile.ErrMutationUncertain, profile.ErrReadUnavailable, profile.ErrConflict)
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(reported, actualClose), "indeterminate")
	if !bytes.Equal(after, f.profileBytes(t)) {
		t.Fatal("completion classification changed published profile bytes")
	}
}

func TestAuditImportMutationCompletionActualSeedPartialPublication(t *testing.T) {
	f := newAuditImportReadCompletionFixture(t)
	original := f.profileBytes(t)
	controller := f.controller(t)
	first := profile.New("seed-published-profile", "PRIVATE_SEED_PUBLISHED", "byedpi")
	first.Probe.Host = "127.0.0.1"
	invalid := profile.New("seed-invalid-profile", "PRIVATE_SEED_INVALID", "byedpi")
	invalid.Version = 0
	if first.Validate() != nil || invalid.Validate() == nil {
		t.Fatal("partial Seed source fixture invalid")
	}
	operationErr := f.store.Seed([]profile.Profile{first, invalid})
	if !errors.Is(operationErr, profile.ErrMutationUncertain) {
		f.preserve = true
		t.Fatal("actual partial Seed mutation uncertainty not retained")
	}
	// This fixture expects a pure validation failure after actual publication.
	// Unexpected native I/O or cleanup uncertainty retains its owned evidence.
	var nativeFailure *os.PathError
	if errors.As(operationErr, &nativeFailure) || errors.Is(operationErr, profile.ErrReadUnavailable) || errors.Is(operationErr, filelock.ErrCloseUncertain) {
		f.preserve = true
		t.Fatal("partial Seed fixture encountered native uncertainty")
	}
	published, err := f.store.GetContext(context.Background(), first.ID)
	if err != nil {
		f.preserve = true
		t.Fatal("actual partial Seed profile read unconfirmed")
	}
	if published.ID != first.ID || published.Name != first.Name || published.UpdatedAt.IsZero() {
		t.Fatal("actual partial Seed publication not observed")
	}
	publishedPath := filepath.Join(f.root, "profiles", first.ID+".json")
	publishedBytes, err := fileinput.Read(context.Background(), publishedPath, 1<<20)
	if err != nil {
		f.preserve = true
		t.Fatal("actual partial Seed bytes read unconfirmed")
	}
	assertMissing := func() {
		t.Helper()
		for _, path := range []string{filepath.Join(f.root, "profiles", invalid.ID+".json"), filepath.Join(f.root, "presets-initialized")} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				f.preserve = true
				t.Fatal("partial Seed unexpectedly published a later profile or marker")
			}
		}
	}
	assertMissing()
	actualClose := f.close(t, controller)
	if actualClose != nil {
		t.Fatal("actual partial Seed controller Close unconfirmed")
	}
	probe := f.controller(t)
	if f.close(t, probe) != nil {
		t.Fatal("partial Seed independent controller Close unconfirmed")
	}
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(operationErr, actualClose), "indeterminate")
	for _, known := range []error{profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied} {
		// The underlying partial Seed error is real; only these cofactors are synthetic.
		cofailures := errors.Join(operationErr, profile.ErrReadUnavailable, known)
		assertAuditImportReadCompletion(t, completeReviewedProfileImport(cofailures, actualClose), "indeterminate")
	}
	after, err := fileinput.Read(context.Background(), publishedPath, 1<<20)
	if err != nil {
		f.preserve = true
		t.Fatal("retained partial Seed bytes read unconfirmed")
	}
	if !bytes.Equal(publishedBytes, after) || !bytes.Equal(original, f.profileBytes(t)) {
		t.Fatal("completion classification changed retained profile bytes")
	}
	assertMissing()
}
