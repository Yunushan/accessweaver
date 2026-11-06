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

func TestProfileReadUncertaintyHasPrivateUnavailablePrecedence(t *testing.T) {
	private := &os.PathError{Op: "PRIVATE_OPERATION", Path: "PRIVATE_PROFILE_PATH", Err: errors.New("PRIVATE_CLOSE_CAUSE")}
	for _, uncertain := range []error{profile.ErrReadUnavailable, filelock.ErrCloseUncertain} {
		for _, cofactor := range []error{fs.ErrNotExist, profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied, managed.ErrUnavailable, context.Canceled} {
			for _, fallback := range []int{http.StatusNotFound, http.StatusBadRequest, http.StatusInternalServerError} {
				response := httptest.NewRecorder()
				failProfile(response, errors.Join(cofactor, private, uncertain), fallback)
				var body map[string]string
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal("invalid failure response")
				}
				if response.Code != http.StatusServiceUnavailable || body["error"] != profile.ErrReadUnavailable.Error() || response.Header().Get("Retry-After") != "" || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE")) {
					t.Fatal("uncertain read was exposed or classified as a retryable refusal")
				}
			}
		}
	}
	busy := httptest.NewRecorder()
	failProfile(busy, profile.ErrStoreBusy, http.StatusNotFound)
	if busy.Code != http.StatusServiceUnavailable || busy.Header().Get("Retry-After") != "1" {
		t.Fatal("clean store contention lost its existing admission response")
	}
}

func TestProfileReadAuditFailuresUseTheirFixedMessages(t *testing.T) {
	for _, primary := range []error{audit.ErrRecorderUnavailable, audit.ErrRecordedUncertain} {
		response := httptest.NewRecorder()
		failProfile(response, errors.Join(primary, profile.ErrReadUnavailable, errors.New("PRIVATE_NATIVE_CAUSE")), http.StatusNotFound)
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal("invalid audit failure response")
		}
		if response.Code != http.StatusServiceUnavailable || body["error"] != primary.Error() || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE")) {
			t.Fatal("joined audit failure exposed private causes or lost its recovery message")
		}
	}
}

func TestAuditedProfileReadUncertaintyCannotBecomeRefusal(t *testing.T) {
	for _, uncertain := range []error{profile.ErrReadUnavailable, filelock.ErrCloseUncertain} {
		for _, cofactor := range []error{profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied, managed.ErrUnavailable} {
			server, journal, output := auditedAPIFixture(t)
			calls := 0
			err := server.profileChange(context.Background(), "profile.write", func(context.Context) error {
				calls++
				return errors.Join(cofactor, uncertain, errors.New("PRIVATE_READ_CLOSE_CAUSE"))
			})
			if !errors.Is(err, audit.ErrRecordedUncertain) || calls != 1 || len(journal.events) != 2 || journal.events[0].Outcome != "intent" || journal.events[1].Outcome != "indeterminate" {
				t.Fatal("read uncertainty was recorded as a known refusal")
			}
			if err := server.profileChange(context.Background(), "profile.write", func(context.Context) error { calls++; return nil }); !errors.Is(err, audit.ErrRecorderUnavailable) || calls != 1 {
				t.Fatal("uncertain transaction admitted another mutation")
			}
			if bytes.Contains(journal.lines, []byte("PRIVATE")) || bytes.Contains(output.Bytes(), []byte("PRIVATE")) {
				t.Fatal("audit exposed private read causes")
			}
			if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(journal.lines), journal.start, journal.head); err != nil {
				t.Fatal("invalid uncertainty audit segment")
			}
		}
	}
}

func TestAuditedProfileWriteKeepsCompletedOutcomeWhenResponseReadFails(t *testing.T) {
	server, journal, _ := auditedAPIFixture(t)
	selected := profile.New("readback-profile", "PRIVATE_SAVED_PROFILE", "byedpi")
	path := filepath.Join(server.Store.Root, "profiles", selected.ID+".json")
	writes := 0
	journal.afterAppend = func(event audit.Event) {
		if event.Action != "profile.write" || event.Outcome != "completed" {
			return
		}
		writes++
		if writes == 1 {
			if err := os.WriteFile(path, bytes.Repeat([]byte(" "), (1<<20)+1), 0600); err != nil {
				t.Fatal("owned post-publication read fault unavailable")
			}
		}
	}
	response := request(t, server, "PUT", "/api/v1/profiles/"+selected.ID, selected, server.Token, "localhost")
	if response.Code != http.StatusServiceUnavailable || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE")) {
		t.Fatal("post-publication read failure was exposed or returned success")
	}
	if writes != 1 || len(journal.events) != 2 || journal.events[0].Outcome != "intent" || journal.events[1].Outcome != "completed" {
		t.Fatal("response read failure rewrote or replayed the completed mutation")
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != (1<<20)+1 {
		t.Fatal("response handling replayed the write")
	}
	selected.ID = "next-readback-profile"
	response = request(t, server, "PUT", "/api/v1/profiles/"+selected.ID, selected, server.Token, "localhost")
	if response.Code != http.StatusOK || writes != 2 || len(journal.events) != 4 || journal.events[3].Outcome != "completed" {
		t.Fatal("completed mutation was incorrectly treated as an uncertain audit transaction")
	}
	if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(journal.lines), journal.start, journal.head); err != nil {
		t.Fatal("invalid completed write audit segment")
	}
}

func TestCleanMissingProfileRemainsNotFoundAndCanBeCreated(t *testing.T) {
	server := makeServer(t)
	selected := profile.New("new-read-profile", "owned clean-absence fixture", "byedpi")
	response := request(t, server, "GET", "/api/v1/profiles/"+selected.ID, nil, server.Token, "localhost")
	var missing map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &missing); err != nil || response.Code != http.StatusNotFound || missing["error"] != "saved profile was not found" {
		t.Fatal("clean absence changed or disclosed private details")
	}
	response = request(t, server, "PUT", "/api/v1/profiles/"+selected.ID, selected, server.Token, "localhost")
	if response.Code != http.StatusOK {
		t.Fatal("clean missing profile no longer supports creation")
	}
	response = request(t, server, "GET", "/api/v1/profiles/"+selected.ID, nil, server.Token, "localhost")
	if response.Code != http.StatusOK {
		t.Fatal("newly created profile cannot be read")
	}
}
