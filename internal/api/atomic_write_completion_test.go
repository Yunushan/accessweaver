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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/fileidentity"
	"github.com/Yunushan/accessweaver/internal/fileinput"
	"github.com/Yunushan/accessweaver/internal/filelock"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/profile"
)

func TestAtomicWriteAPIUncertaintyHasPrivateInspectionPrecedence(t *testing.T) {
	private := &os.PathError{Op: "PRIVATE_REPLACE", Path: "PRIVATE_RANDOM_STAGE", Err: errors.New("PRIVATE_NATIVE_CAUSE")}
	for _, cofactor := range []error{profile.ErrReadUnavailable, filelock.ErrCloseUncertain, fs.ErrNotExist, profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied, managed.ErrUnavailable, context.Canceled} {
		response := httptest.NewRecorder()
		failProfile(response, errors.Join(cofactor, private, profile.ErrAtomicWriteUncertain), http.StatusBadRequest)
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal("invalid file update failure response")
		}
		if response.Code != http.StatusServiceUnavailable || body["error"] != profile.ErrAtomicWriteUncertain.Error() || response.Header().Get("Retry-After") != "" || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE")) {
			t.Fatal("file update uncertainty exposed private causes or became a known refusal")
		}
	}
	for _, primary := range []error{profile.ErrMutationUncertain, audit.ErrRecorderUnavailable, audit.ErrRecordedUncertain} {
		response := httptest.NewRecorder()
		failProfile(response, errors.Join(primary, profile.ErrAtomicWriteUncertain, private), http.StatusBadRequest)
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusServiceUnavailable || body["error"] != primary.Error() {
			t.Fatal("atomic cofactor displaced required mutation or audit inspection guidance")
		}
	}
}

func TestAuditedProfileAtomicWriteUncertaintyCannotBecomeRefusal(t *testing.T) {
	for _, cofactor := range []error{profile.ErrConflict, profile.ErrStoreBusy, managed.ErrDenied, managed.ErrUnavailable} {
		server, journal, output := auditedAPIFixture(t)
		calls := 0
		// A finite error-category composition contract, not a kernel fault.
		err := server.profileChange(context.Background(), "profile.write", func(context.Context) error {
			calls++
			return errors.Join(profile.ErrAtomicWriteUncertain, cofactor, errors.New("PRIVATE_STAGE_CAUSE"))
		})
		if !errors.Is(err, audit.ErrRecordedUncertain) || calls != 1 || len(journal.events) != 2 || journal.events[1].Outcome != "indeterminate" {
			t.Fatal("file update uncertainty became a known refusal or success")
		}
		if err := server.profileChange(context.Background(), "profile.write", func(context.Context) error { calls++; return nil }); !errors.Is(err, audit.ErrRecorderUnavailable) || calls != 1 {
			t.Fatal("uncertain recorder dispatched another mutation")
		}
		if bytes.Contains(journal.lines, []byte("PRIVATE")) || bytes.Contains(output.Bytes(), []byte("PRIVATE")) {
			t.Fatal("file update error leaked through audit records")
		}
		if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(journal.lines), journal.start, journal.head); err != nil {
			t.Fatal("invalid file update audit segment")
		}
	}
}

func TestAtomicWriteAPIStartFailureRetainsGeneratedState(t *testing.T) {
	root, err := os.MkdirTemp("", "accessweaver-atomic-http-")
	if err != nil {
		t.Fatal("owned API fixture unavailable")
	}
	identity, err := fileidentity.FromPath(root, false)
	if err != nil || identity.Kind != fileidentity.Directory {
		t.Fatal("owned API fixture identity unavailable")
	}
	preserve := false
	t.Cleanup(func() {
		// The HTTP privacy boundary intentionally hides the native Close cause.
		// A response-only uncertainty retains this small source-owned fixture;
		// this test makes no proof that an unknown native owner can be removed.
		if preserve || t.Failed() {
			return
		}
		current, err := fileidentity.FromPath(root, false)
		if err != nil || current.ID != identity.ID || current.Kind != identity.Kind {
			t.Error("changed API fixture retained")
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("owned API fixture cleanup failed")
		}
	})
	guard := managed.NewGuard(func() (*managed.Authority, error) { return nil, nil })
	store, err := profile.NewStoreWithGuard(root, guard)
	if err != nil {
		preserve = true
		t.Fatal("owned API store unavailable")
	}
	manager := engine.NewManagerWithGuard(root, guard)
	server, err := New(store, manager, nil)
	if err != nil {
		t.Fatal("owned API server unavailable")
	}
	server.Policy = guard
	name := "ciadpi"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(root, name)
	// No executable header, interpreter or command payload. Preparation must
	// fail before launch, independently covered by engine's owner-boundary spy.
	if err := os.WriteFile(binary, []byte("owned inert adapter fixture"), 0700); err != nil {
		preserve = true
		t.Fatal("owned inert adapter unavailable")
	}
	selected := profile.New("atomic-http-profile", "PRIVATE_PROFILE_NAME", "byedpi")
	selected.Binary = binary
	selected.Routing.IncludeDomains = []string{"include.example"}
	selected.Routing.ExcludeDomains = []string{"exclude.example"}
	if err := store.Save(selected); err != nil {
		preserve = true
		t.Fatal("owned API profile setup failed")
	}
	selected, err = store.Get(selected.ID)
	if err != nil {
		preserve = true
		t.Fatal("owned API revision unavailable")
	}
	response := request(t, server, "POST", "/api/v1/preview", selected, server.Token, "localhost")
	var plan engine.LaunchPlan
	if err := json.Unmarshal(response.Body.Bytes(), &plan); err != nil || response.Code != http.StatusOK || !plan.Ready {
		t.Fatal("read-only owned launch preview unavailable")
	}
	generated := filepath.Join(root, "generated")
	if _, err := os.Lstat(generated); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("preview created generated files")
	}
	blocked := filepath.Join(generated, selected.ID+"-exclude.txt")
	if err := os.MkdirAll(blocked, 0700); err != nil {
		t.Fatal("owned publish obstruction unavailable")
	}
	if err := os.WriteFile(filepath.Join(blocked, "owned-blocker"), []byte("unchanged directory evidence"), 0600); err != nil {
		preserve = true
		t.Fatal("owned obstruction evidence unavailable")
	}
	blockedIdentity, err := fileidentity.FromPath(blocked, false)
	if err != nil {
		preserve = true
		t.Fatal("owned obstruction identity unavailable")
	}
	response = request(t, server, "POST", "/api/v1/start", map[string]any{"id": selected.ID, "confirm": true, "expectedUpdatedAt": selected.UpdatedAt.Format(time.RFC3339Nano)}, server.Token, "localhost")
	preserve = true // retain actual failed-update evidence; no product cleanup claim
	var failure map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || response.Code != http.StatusServiceUnavailable || failure["error"] != profile.ErrAtomicWriteUncertain.Error() || response.Header().Get("Retry-After") != "" || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE")) {
		t.Fatal("actual generated-file failure was exposed or reported as success/refusal")
	}
	status := manager.Snapshot()
	if status.State != "stopped" || status.PID != 0 || status.LifecyclePending {
		t.Fatal("failed generation admitted a process owner")
	}
	include, err := fileinput.Read(context.Background(), filepath.Join(generated, selected.ID+"-include.txt"), 64)
	if err != nil || string(include) != "include.example\n" {
		t.Fatal("earlier generated input was rolled back or changed")
	}
	clear(include)
	after, err := fileidentity.FromPath(blocked, false)
	if err != nil || after.ID != blockedIdentity.ID || after.Kind != fileidentity.Directory {
		t.Fatal("failed publication replaced the owned obstruction")
	}
	blocker, err := fileinput.Read(context.Background(), filepath.Join(blocked, "owned-blocker"), 64)
	if err != nil || string(blocker) != "unchanged directory evidence" {
		t.Fatal("owned obstruction evidence changed")
	}
	clear(blocker)
	entries, err := os.ReadDir(generated)
	if err != nil {
		t.Fatal("owned generated inputs unavailable")
	}
	stages := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".accessweaver-") {
			continue
		}
		stages++
		data, err := fileinput.Read(context.Background(), filepath.Join(generated, entry.Name()), 64)
		if err != nil || string(data) != "exclude.example\n" {
			t.Fatal("failed generated stage was lost or changed")
		}
		clear(data)
	}
	if stages != 1 {
		t.Fatal("failed publication did not retain exactly its owned stage")
	}
}
