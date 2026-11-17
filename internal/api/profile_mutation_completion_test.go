package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestProfileMutationUncertaintyHasPrivateInspectionPrecedence(t *testing.T) {
	private := &os.PathError{Op: "PRIVATE_COMPLETION", Path: "PRIVATE_PROFILE_PATH", Err: errors.New("PRIVATE_CLOSE_CAUSE")}
	for _, cofactor := range []error{profile.ErrReadUnavailable, filelock.ErrCloseUncertain, fs.ErrNotExist, profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied, managed.ErrUnavailable, context.Canceled} {
		for _, fallback := range []int{http.StatusNotFound, http.StatusBadRequest, http.StatusInternalServerError} {
			response := httptest.NewRecorder()
			failProfile(response, errors.Join(cofactor, private, profile.ErrMutationUncertain), fallback)
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal("invalid mutation completion response")
			}
			if response.Code != http.StatusServiceUnavailable || body["error"] != profile.ErrMutationUncertain.Error() || response.Header().Get("Retry-After") != "" || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE")) {
				t.Fatal("mutation uncertainty lost its fixed inspection message or became retryable")
			}
		}
	}
}

func TestProfileMutationAuditFailureKeepsItsRequiredRecoveryMessage(t *testing.T) {
	for _, primary := range []error{audit.ErrRecorderUnavailable, audit.ErrRecordedUncertain} {
		response := httptest.NewRecorder()
		failProfile(response, errors.Join(primary, profile.ErrMutationUncertain, errors.New("PRIVATE_PUBLICATION_CAUSE")), http.StatusBadRequest)
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal("invalid audit recovery response")
		}
		if response.Code != http.StatusServiceUnavailable || body["error"] != primary.Error() || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE")) {
			t.Fatal("mutation cofactor replaced required audit recovery guidance")
		}
	}
}

func TestAuditedProfileMutationPublicationUncertaintyCannotBecomeRefusal(t *testing.T) {
	for _, cofactor := range []error{profile.ErrReadUnavailable, filelock.ErrCloseUncertain, profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied, managed.ErrUnavailable} {
		server, journal, output := auditedAPIFixture(t)
		selected := profile.New("published-profile", "PRIVATE_PUBLISHED_PROFILE", "byedpi")
		reportedAfterSuccess := false
		calls := 0
		err := server.profileChange(context.Background(), "profile.write", func(ctx context.Context) error {
			calls++
			if err := server.Store.SaveIfUnchangedContext(ctx, selected); err != nil {
				return err
			}
			// Model a reported completion cofailure only AFTER a real successful
			// Store write has returned. Native Close injection is tested inside
			// profile; this callback does not fabricate a kernel result.
			reportedAfterSuccess = true
			return errors.Join(profile.ErrMutationUncertain, cofactor, errors.New("PRIVATE_REPORTED_COMPLETION_CAUSE"))
		})
		if !reportedAfterSuccess || calls != 1 || !errors.Is(err, audit.ErrRecordedUncertain) || len(journal.events) != 2 || journal.events[0].Outcome != "intent" || journal.events[1].Outcome != "indeterminate" {
			t.Fatal("published mutation was recorded as a known refusal or success")
		}
		saved, err := server.Store.GetContext(context.Background(), selected.ID)
		if err != nil || saved.Name != selected.Name || saved.UpdatedAt.IsZero() {
			t.Fatal("uncertain completion rolled back or lost the real publication")
		}
		if err := server.profileChange(context.Background(), "profile.write", func(context.Context) error { calls++; return nil }); !errors.Is(err, audit.ErrRecorderUnavailable) || calls != 1 {
			t.Fatal("uncertain recorder replayed or admitted another mutation")
		}
		if bytes.Contains(journal.lines, []byte("PRIVATE")) || bytes.Contains(output.Bytes(), []byte("PRIVATE")) {
			t.Fatal("completion cofactor leaked through audit output")
		}
		if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(journal.lines), journal.start, journal.head); err != nil {
			t.Fatal("invalid publication uncertainty audit segment")
		}
	}
}

func TestAuditedProfileMutationSeedPartialPublicationIsIndeterminate(t *testing.T) {
	server, journal, output := auditedAPIFixture(t)
	first := profile.New("partial-seed-first", "PRIVATE_FIRST_SEED", "byedpi")
	second := profile.New("partial-seed-second", "", "byedpi")
	var seedErr error
	err := server.profileChange(context.Background(), "profile.write", func(context.Context) error {
		seedErr = server.Store.Seed([]profile.Profile{first, second})
		return seedErr
	})
	if !errors.Is(seedErr, profile.ErrMutationUncertain) || !errors.Is(err, audit.ErrRecordedUncertain) || len(journal.events) != 2 || journal.events[1].Outcome != "indeterminate" {
		t.Fatal("partly published preset initialization was recorded as absent or complete")
	}
	saved, err := server.Store.Get(first.ID)
	if err != nil || saved.Name != first.Name {
		t.Fatal("partial seed publication was rolled back")
	}
	if _, err := server.Store.Get(second.ID); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("invalid second preset was published")
	}
	if _, err := os.Lstat(filepath.Join(server.Store.Root, "presets-initialized")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("partial seed incorrectly published its final marker")
	}
	if bytes.Contains(journal.lines, []byte("PRIVATE")) || bytes.Contains(output.Bytes(), []byte("PRIVATE")) {
		t.Fatal("partial seed contents leaked into audit records")
	}
	if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(journal.lines), journal.start, journal.head); err != nil {
		t.Fatal("invalid partial seed audit segment")
	}
}
