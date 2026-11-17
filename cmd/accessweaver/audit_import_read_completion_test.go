package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func assertAuditImportReadCompletion(t *testing.T, got importOutcome, outcome string) {
	t.Helper()
	var failure error
	switch outcome {
	case "completed":
	case "refused":
		failure = errAuditImportRefused
	case "indeterminate":
		failure = errAuditImportUncertain
	default:
		t.Fatal("invalid source fixture outcome")
	}
	if got.outcome != outcome || !got.mutationStarted || got.failure != failure {
		t.Fatal("import completion changed its fixed outcome or privacy contract")
	}
}

// These are completion-category contracts, not injected native Close failures.
func TestAuditImportReadCompletionKnownRefusalsAndUncertainty(t *testing.T) {
	for _, known := range []struct {
		name  string
		cause error
	}{
		{"conflict", profile.ErrConflict}, {"busy", profile.ErrStoreBusy}, {"policy-denied", managed.ErrDenied},
	} {
		t.Run(known.name, func(t *testing.T) {
			assertAuditImportReadCompletion(t, completeReviewedProfileImport(known.cause, nil), "refused")
			privateClose := &os.PathError{Op: "close", Path: "PRIVATE_CONTROLLER_PATH", Err: errors.New("PRIVATE_CONTROLLER_CAUSE")}
			assertAuditImportReadCompletion(t, completeReviewedProfileImport(known.cause, privateClose), "indeterminate")
			for _, uncertain := range []error{profile.ErrReadUnavailable, filelock.ErrCloseUncertain} {
				joined := errors.Join(known.cause, uncertain, errors.New("PRIVATE_READ_CAUSE"))
				assertAuditImportReadCompletion(t, completeReviewedProfileImport(joined, nil), "indeterminate")
				wrapped := &os.PathError{Op: "read", Path: "PRIVATE_READ_PATH", Err: joined}
				assertAuditImportReadCompletion(t, completeReviewedProfileImport(wrapped, nil), "indeterminate")
			}
		})
	}
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(nil, nil), "completed")
	for _, failure := range []error{profile.ErrReadUnavailable, filelock.ErrCloseUncertain, context.Canceled, errors.New("PRIVATE_UNKNOWN_CAUSE")} {
		assertAuditImportReadCompletion(t, completeReviewedProfileImport(failure, nil), "indeterminate")
		assertAuditImportReadCompletion(t, completeReviewedProfileImport(nil, failure), "indeterminate")
	}
}

func TestAuditImportReadCompletionControllerAcquisitionCategories(t *testing.T) {
	for _, known := range []error{filelock.ErrBusy, errors.New("PRIVATE_ACQUISITION_CAUSE")} {
		assertAuditImportReadCompletion(t, failedReviewedProfileImportAcquisition(known), "refused")
		uncertain := errors.Join(known, filelock.ErrCloseUncertain, errors.New("PRIVATE_ACQUISITION_CLOSE_CAUSE"))
		assertAuditImportReadCompletion(t, failedReviewedProfileImportAcquisition(uncertain), "indeterminate")
		wrapped := &os.PathError{Op: "open", Path: "PRIVATE_ACQUISITION_PATH", Err: uncertain}
		assertAuditImportReadCompletion(t, failedReviewedProfileImportAcquisition(wrapped), "indeterminate")
	}
}

type auditImportReadCompletionLease struct {
	lock      *filelock.Lock
	attempted bool
	failure   error
}
type auditImportReadCompletionFixture struct {
	root     string
	store    *profile.Store
	current  profile.Profile
	preserve bool
	leases   []*auditImportReadCompletionLease
}

func newAuditImportReadCompletionFixture(t *testing.T) *auditImportReadCompletionFixture {
	t.Helper()
	root, err := os.MkdirTemp("", "accessweaver-import-read-completion-")
	if err != nil {
		t.Fatal("owned import fixture unavailable")
	}
	state, err := fileidentity.FromPath(root, false)
	if err != nil || state.Kind != fileidentity.Directory {
		t.Fatal("owned import fixture identity unavailable")
	}
	f := &auditImportReadCompletionFixture{root: root}
	t.Cleanup(func() {
		for _, lease := range f.leases {
			if !lease.attempted {
				f.close(t, lease)
			}
		}
		if f.preserve {
			t.Error("unconfirmed import fixture retained")
			return
		}
		current, err := fileidentity.FromPath(root, false)
		if err != nil || current.Kind != state.Kind || current.ID != state.ID {
			t.Error("changed import fixture retained")
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("owned import fixture cleanup failed")
		}
	})
	// No host configuration, machine policy, HOME lookup or default Store guard.
	f.store, err = profile.NewStoreWithGuard(root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	if err != nil {
		f.preserve = true
		t.Fatal("owned profile Store unavailable")
	}
	p := profile.New("reviewed-profile", "PRIVATE_IMPORT_PROFILE", "byedpi")
	p.Args = []string{"PRIVATE_IMPORT_ARGUMENT"}
	p.Probe.Host = "127.0.0.1"
	if err = f.store.Save(p); err != nil {
		f.preserve = true
		t.Fatal("owned profile setup failed")
	}
	f.current, err = f.store.GetContext(context.Background(), p.ID)
	if err != nil {
		f.preserve = true
		t.Fatal("owned reviewed profile unavailable")
	}
	return f
}
func (f *auditImportReadCompletionFixture) own(lock *filelock.Lock) *auditImportReadCompletionLease {
	lease := &auditImportReadCompletionLease{lock: lock}
	f.leases = append(f.leases, lease)
	return lease
}
func (f *auditImportReadCompletionFixture) controller(t *testing.T) *auditImportReadCompletionLease {
	t.Helper()
	lock, err := filelock.TryAcquire(filepath.Join(f.root, ".controller.lock"))
	var lease *auditImportReadCompletionLease
	if lock != nil {
		lease = f.own(lock)
	}
	if err != nil || lease == nil {
		f.preserve = true
		t.Fatal("owned controller acquisition unavailable")
	}
	return lease
}
func (f *auditImportReadCompletionFixture) close(t *testing.T, lease *auditImportReadCompletionLease) error {
	t.Helper()
	if !lease.attempted {
		lease.attempted = true
		lease.failure = lease.lock.Close()
		if lease.failure != nil {
			f.preserve = true
			t.Error("actual controller Close unconfirmed")
		}
	}
	return lease.failure
}
func (f *auditImportReadCompletionFixture) profileBytes(t *testing.T) []byte {
	t.Helper()
	value, err := fileinput.Read(context.Background(), filepath.Join(f.root, "profiles", f.current.ID+".json"), 1<<20)
	if err != nil {
		f.preserve = true
		t.Fatal("owned profile bytes unavailable")
	}
	return value
}

func TestAuditImportReadCompletionActualConflictAndControllerClose(t *testing.T) {
	f := newAuditImportReadCompletionFixture(t)
	before := f.profileBytes(t)
	controller := f.controller(t)
	draft := f.current.Copy()
	draft.UpdatedAt = time.Time{}
	operationErr := f.store.SaveIfUnchangedContext(context.Background(), draft)
	if !errors.Is(operationErr, profile.ErrConflict) {
		t.Fatal("actual optimistic refusal not reached")
	}
	actualClose := f.close(t, controller)
	if actualClose != nil {
		t.Fatal("actual controller Close failed before semantic injection")
	}
	// The independent acquisition proves physical release. The following error
	// models a reported cleanup cofailure AFTER that successful actual Close.
	probe := f.controller(t)
	if err := f.close(t, probe); err != nil {
		t.Fatal("controller release probe Close unconfirmed")
	}
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(operationErr, actualClose), "refused")
	reportedClose := errors.New("PRIVATE_REPORTED_CONTROLLER_CLOSE_CAUSE")
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(operationErr, reportedClose), "indeterminate")
	// The public read category is synthetic here; this is not a kernel read fault.
	readCofailure := errors.Join(operationErr, profile.ErrReadUnavailable)
	assertAuditImportReadCompletion(t, completeReviewedProfileImport(readCofailure, actualClose), "indeterminate")
	after := f.profileBytes(t)
	if !bytes.Equal(before, after) {
		t.Fatal("completion classification changed existing profile bytes")
	}
}

func TestAuditImportReadCompletionActualContentionAndCleanupCategory(t *testing.T) {
	f := newAuditImportReadCompletionFixture(t)
	before := f.profileBytes(t)
	controller := f.controller(t)
	contender, err := filelock.TryAcquire(filepath.Join(f.root, ".controller.lock"))
	if contender != nil {
		f.own(contender)
	}
	if err != filelock.ErrBusy || contender != nil {
		f.preserve = true
		t.Fatal("actual controller contention not reached")
	}
	assertAuditImportReadCompletion(t, failedReviewedProfileImportAcquisition(err), "refused")
	// Failed-acquisition Close injection is private to filelock's own tests.
	// This verifies the CLI consumes that public category conservatively.
	reportedCleanup := errors.Join(err, filelock.ErrCloseUncertain, errors.New("PRIVATE_REPORTED_ACQUISITION_CLOSE_CAUSE"))
	assertAuditImportReadCompletion(t, failedReviewedProfileImportAcquisition(reportedCleanup), "indeterminate")
	if err := f.close(t, controller); err != nil {
		t.Fatal("actual original controller Close unconfirmed")
	}
	probe := f.controller(t)
	if err := f.close(t, probe); err != nil {
		t.Fatal("fresh controller Close unconfirmed")
	}
	after := f.profileBytes(t)
	if !bytes.Equal(before, after) {
		t.Fatal("acquisition classification changed existing profile bytes")
	}
}
