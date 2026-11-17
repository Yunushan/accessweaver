package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/Yunushan/accessweaver/internal/audit"
	"github.com/Yunushan/accessweaver/internal/profile"
)

// This fixture records real API/store operations using the canonical chain.
// Native protected-storage coverage is supplied by the Linux roundtrip test.
type apiAuditJournal struct {
	start, head   audit.Checkpoint
	lines         []byte
	events        []audit.Event
	calls, failAt int
	afterAppend   func(audit.Event)
}

func (j *apiAuditJournal) Append(ctx context.Context, e audit.Event) (audit.Checkpoint, error) {
	j.calls++
	if j.calls == j.failAt {
		return audit.Checkpoint{}, errors.New("PRIVATE_DISK")
	}
	if ctx.Err() != nil {
		return audit.Checkpoint{}, ctx.Err()
	}
	data, next, err := audit.Append(j.head, e)
	if err != nil {
		return audit.Checkpoint{}, err
	}
	j.lines = append(j.lines, data...)
	j.head = next
	j.events = append(j.events, e)
	if j.afterAppend != nil {
		j.afterAppend(e)
	}
	return next, nil
}
func (j *apiAuditJournal) Snapshot(context.Context) ([]byte, audit.Checkpoint, audit.Checkpoint, error) {
	return bytes.Clone(j.lines), j.start, j.head, nil
}
func (j *apiAuditJournal) Close() error { return nil }
func auditedAPIFixture(t *testing.T) (*Server, *apiAuditJournal, *bytes.Buffer) {
	t.Helper()
	s := makeServer(t)
	start, err := audit.NewStream(audit.Producer{ActorClass: "user", ActorSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SourceCommit: "unknown", SourceState: "unknown", Target: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	j := &apiAuditJournal{start: start, head: start}
	out := &bytes.Buffer{}
	recorder, err := audit.NewRecorder(context.Background(), j, start, start, out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	server, err := NewProfileAudited(s.Store, s.Manager, nil, recorder)
	if err != nil {
		t.Fatal(err)
	}
	return server, j, out
}
func TestAuditedProfileActualCRUDAndRevisionRefusal(t *testing.T) {
	s, j, out := auditedAPIFixture(t)
	p := profile.New("audit-profile", "PRIVATE_PROFILE_NAME", "byedpi")
	response := request(t, s, "PUT", "/api/v1/profiles/"+p.ID, p, s.Token, "localhost")
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	var saved profile.Profile
	if err := json.Unmarshal(response.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if len(j.events) != 2 || j.events[0].Action != "profile.write" || j.events[1].Outcome != "completed" {
		t.Fatal("missing write audit")
	}
	response = request(t, s, "PUT", "/api/v1/profiles/"+p.ID, p, s.Token, "localhost")
	if response.Code != 409 || j.events[3].Outcome != "refused" {
		t.Fatal("stale save not refused", response.Code, j.events)
	}
	response = request(t, s, "DELETE", "/api/v1/profiles/"+p.ID, map[string]any{"expectedUpdatedAt": saved.UpdatedAt}, s.Token, "localhost")
	if response.Code != 200 || len(j.events) != 6 || j.events[4].Action != "profile.delete" || j.events[5].Outcome != "completed" {
		t.Fatal("delete not recorded", response.Code)
	}
	if _, err := s.Store.Get(p.ID); err == nil {
		t.Fatal("delete did not occur")
	}
	if bytes.Contains(j.lines, []byte("PRIVATE")) || bytes.Contains(out.Bytes(), []byte("PRIVATE")) {
		t.Fatal("profile name leaked")
	}
	if _, err := audit.VerifySegment(context.Background(), bytes.NewReader(j.lines), j.start, j.head); err != nil {
		t.Fatal(err)
	}
}
func TestAuditedAPIFailClosedBeforeStoreAndAfterUncertainResult(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			s, j, _ := auditedAPIFixture(t)
			j.failAt = failAt
			p := profile.New("audit-profile", "PRIVATE_NAME", "byedpi")
			w := request(t, s, "PUT", "/api/v1/profiles/"+p.ID, p, s.Token, "localhost")
			if w.Code != 503 || bytes.Contains(w.Body.Bytes(), []byte("PRIVATE")) {
				t.Fatal("unsafe failure", w.Code, w.Body.String())
			}
			_, err := s.Store.Get(p.ID)
			if (failAt == 1) != (err != nil) {
				t.Fatal("wrong mutation outcome", err)
			}
			calls := j.calls
			p.ID = "second-profile"
			w = request(t, s, "PUT", "/api/v1/profiles/"+p.ID, p, s.Token, "localhost")
			if w.Code != 503 || j.calls != calls {
				t.Fatal("failed recorder reused")
			}
			if _, err := s.Store.Get(p.ID); err == nil {
				t.Fatal("second operation dispatched")
			}
		})
	}
}
func TestAuditedDesktopRefusesUnconnectedActionsAndKeepsSessionChecks(t *testing.T) {
	s, j, _ := auditedAPIFixture(t)
	for _, tc := range []struct{ method, path string }{{"POST", "/api/v1/start"}, {"POST", "/api/v1/stop"}, {"POST", "/api/v1/system/start"}, {"POST", "/api/v1/system/cancel"}, {"POST", "/api/v1/system/folder"}, {"POST", "/api/v1/system/preview"}, {"POST", "/api/v1/diagnose"}, {"GET", "/api/v1/support"}, {"GET", "/api/v1/system/history"}} {
		w := request(t, s, tc.method, tc.path, map[string]any{}, s.Token, "localhost")
		if w.Code != http.StatusForbidden {
			t.Fatal("unconnected action dispatched", tc, w.Code)
		}
	}
	p := profile.New("audit-profile", "Private", "byedpi")
	if w := request(t, s, "PUT", "/api/v1/profiles/"+p.ID, p, "wrong", "localhost"); w.Code != 403 {
		t.Fatal("session check bypassed")
	}
	if len(j.events) != 0 {
		t.Fatal("refused routing/session attempt reached producer")
	}
	for _, path := range []string{"/api/bootstrap", "/api/v1/profiles", "/api/v1/engines", "/api/v1/runtime"} {
		if w := request(t, s, "GET", path, nil, s.Token, "localhost"); w.Code != 200 {
			t.Fatal("read unavailable", path, w.Code)
		}
	}
}
