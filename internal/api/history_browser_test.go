package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func historyBrowserFixture(t *testing.T, records map[string][]byte) *Server {
	t.Helper()
	s := makeServer(t)
	s.Workflows = workflow.NewWithGuard(s.Store.Root, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	directory := filepath.Join(s.Store.Root, "workflows")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range records {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func historyBrowserCapture(t *testing.T, s *Server) workflow.HistoryInventory {
	t.Helper()
	response := request(t, s, http.MethodPost, "/api/v1/system/history/inventory", map[string]any{}, s.Token, "127.0.0.1")
	var inventory workflow.HistoryInventory
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &inventory) != nil || len(inventory.Snapshot) != 48 {
		t.Fatal("explicit API inventory capture did not return its durable identity")
	}
	return inventory
}

func historyBrowserPage(t *testing.T, s *Server, query string) workflow.HistoryPage {
	t.Helper()
	response := request(t, s, http.MethodGet, "/api/v1/system/history/page"+query, nil, s.Token, "127.0.0.1")
	var page workflow.HistoryPage
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil {
		t.Fatal("API inventory page was unavailable")
	}
	return page
}

func historyBrowserSHA(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func historyBrowserFind(t *testing.T, page workflow.HistoryPage, revision string) workflow.HistoryRecordSummary {
	t.Helper()
	for _, item := range page.Items {
		if item.Revision == revision {
			return item
		}
	}
	t.Fatal("captured source record was not present in its page")
	return workflow.HistoryRecordSummary{}
}

func TestHistoryBrowserPagesUseDurableCatalogAndKeepPayloadPrivate(t *testing.T) {
	records := make(map[string][]byte)
	for i := 0; i < 129; i++ {
		id := fmt.Sprintf("%048x", i+1)
		records[id+".json"] = []byte(`{"id":"` + id + `","action":"discover","state":"succeeded","error":"PRIVATE_HISTORY_ERROR","result":{"secret":"PRIVATE_HISTORY_RESULT"}}`)
	}
	s := historyBrowserFixture(t, records)
	inventory := historyBrowserCapture(t, s)
	page := historyBrowserPage(t, s, "")
	if inventory.Count != 129 || len(page.Items) != 64 || page.NextCursor == "" {
		t.Fatal("default catalog page did not enforce its finite row count")
	}
	response := request(t, s, http.MethodGet, "/api/v1/system/history/page?limit=128", nil, s.Token, "127.0.0.1")
	if response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE_HISTORY_")) || response.Body.Len() > 256<<10 {
		t.Fatal("bounded page exposed private payload/error content or exceeded metadata size")
	}
	seen := make(map[string]bool)
	cursor := ""
	for {
		query := "?limit=31&snapshot=" + inventory.Snapshot
		if cursor != "" {
			query += "&cursor=" + url.QueryEscape(cursor)
		}
		page = historyBrowserPage(t, s, query)
		for _, item := range page.Items {
			if seen[item.RecordRef] || len(item.ID) != 48 || len(item.Revision) != 64 || !item.ErrorPresent || !item.ResultPresent {
				t.Fatal("catalog paging duplicated a row or lost bounded record metadata")
			}
			seen[item.RecordRef] = true
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 129 {
		t.Fatal("catalog paging omitted retained records")
	}
	historyBrowserCapture(t, s)
	stale := request(t, s, http.MethodGet, "/api/v1/system/history/page?snapshot="+inventory.Snapshot, nil, s.Token, "127.0.0.1")
	if stale.Code != http.StatusConflict {
		t.Fatal("replaced inventory silently reused an old page snapshot")
	}
}

func TestHistoryBrowserDetailAndRawExportBindObservedRecord(t *testing.T) {
	original := []byte("{\n\"id\":\"different-record.json\",\"action\":\"discover\",\"state\":\"failed\",\"error\":\"PRIVATE_HISTORY_ERROR\",\"result\":{\"text\":\"PRIVATE_HISTORY_RESULT\"}}\n")
	other := []byte(`{"id":"other","action":"discover","state":"succeeded","future":true}`)
	malformed := []byte{0xff, '{', 0, 'X'}
	s := historyBrowserFixture(t, map[string][]byte{"observed.json": original, "different-record.json": other, "malformed.json": malformed})
	historyBrowserCapture(t, s)
	page := historyBrowserPage(t, s, "")
	item := historyBrowserFind(t, page, historyBrowserSHA(original))
	if item.ID != "" || item.Classification != "legacy" {
		t.Fatal("stored Job.ID became the observed filename authority")
	}
	base := "/api/v1/system/history/records/" + item.RecordRef
	detailResponse := request(t, s, http.MethodGet, base+"?revision="+item.Revision, nil, s.Token, "127.0.0.1")
	var detail workflow.HistoryRecordDetail
	if detailResponse.Code != http.StatusOK || json.Unmarshal(detailResponse.Body.Bytes(), &detail) != nil || detail.Job == nil || detail.Job.ID != "different-record.json" || !bytes.Contains(detail.Job.Result, []byte("PRIVATE_HISTORY_RESULT")) {
		t.Fatal("selected detail did not preserve the complete explicitly requested record")
	}
	for _, selection := range []struct {
		row  workflow.HistoryRecordSummary
		data []byte
	}{{item, original}, {historyBrowserFind(t, page, historyBrowserSHA(malformed)), malformed}, {historyBrowserFind(t, page, historyBrowserSHA(other)), other}} {
		response := request(t, s, http.MethodGet, "/api/v1/system/history/records/"+selection.row.RecordRef+"/export?revision="+selection.row.Revision, nil, s.Token, "127.0.0.1")
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), selection.data) {
			t.Fatal("raw export transformed bytes, appended framing or followed stored Job.ID")
		}
		if response.Header().Get("Content-Type") != "application/octet-stream" || response.Header().Get("Content-Disposition") != `attachment; filename="accessweaver-workflow-record.bin"` || response.Header().Get("ETag") != `"`+selection.row.Revision+`"` || response.Header().Get("X-AccessWeaver-Revision") != selection.row.Revision || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("private raw export lost its fixed download or content revision headers")
		}
	}
	head := request(t, s, http.MethodHead, base+"/export?revision="+item.Revision, nil, s.Token, "127.0.0.1")
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("X-AccessWeaver-Revision") != item.Revision {
		t.Fatal("HEAD raw export changed revision framing or emitted private body bytes")
	}
	for name, expected := range map[string][]byte{"observed.json": original, "different-record.json": other, "malformed.json": malformed} {
		retained, err := os.ReadFile(filepath.Join(s.Store.Root, "workflows", name))
		if err != nil || !bytes.Equal(retained, expected) {
			t.Fatal("history inspection changed retained source evidence")
		}
	}
	if err := os.WriteFile(filepath.Join(s.Store.Root, "workflows", "observed.json"), []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	stale := request(t, s, http.MethodGet, base+"/export?revision="+item.Revision, nil, s.Token, "127.0.0.1")
	if stale.Code != http.StatusConflict || bytes.Contains(stale.Body.Bytes(), []byte("PRIVATE_HISTORY_")) {
		t.Fatal("changed source bytes were exported under a reviewed stale revision")
	}
}

func TestHistoryBrowserMetadataOnlyDetailRequiresExplicitEmptyRevision(t *testing.T) {
	s := historyBrowserFixture(t, nil)
	if err := os.Mkdir(filepath.Join(s.Store.Root, "workflows", "special.json"), 0700); err != nil {
		t.Fatal(err)
	}
	historyBrowserCapture(t, s)
	page := historyBrowserPage(t, s, "")
	if len(page.Items) != 1 || page.Items[0].RawAvailable || page.Items[0].Revision != "" {
		t.Fatal("special captured entry lost its protected metadata-only shape")
	}
	path := "/api/v1/system/history/records/" + page.Items[0].RecordRef
	response := request(t, s, http.MethodGet, path+"?revision=", nil, s.Token, "127.0.0.1")
	var detail workflow.HistoryRecordDetail
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &detail) != nil || detail.Job != nil || detail.RawAvailable {
		t.Fatal("explicit empty revision could not inspect protected captured metadata")
	}
	for _, suffix := range []string{"", "/export?revision="} {
		response := request(t, s, http.MethodGet, path+suffix, nil, s.Token, "127.0.0.1")
		if response.Code != http.StatusBadRequest {
			t.Fatal("missing detail revision or empty raw revision was accepted")
		}
	}
}

func TestHistoryBrowserStrictRequestsAndReadOnlyMissingInventory(t *testing.T) {
	s := makeServer(t)
	missing := filepath.Join(t.TempDir(), "not-created")
	s.Workflows = workflow.NewWithGuard(missing, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	response := request(t, s, http.MethodGet, "/api/v1/system/history/page", nil, s.Token, "127.0.0.1")
	if response.Code != http.StatusConflict {
		t.Fatal("missing durable inventory was represented as an empty complete page")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only page created its missing root or catalog")
	}
	for _, query := range []string{"?limit=0", "?limit=129", "?limit=+1", "?limit=1&limit=2", "?unknown=PRIVATE_QUERY", "?cursor=", "?snapshot=", "?snapshot=" + strings.Repeat("A", 48), "?cursor=%zz", "?cursor=" + strings.Repeat("a", 257)} {
		response := request(t, s, http.MethodGet, "/api/v1/system/history/page"+query, nil, s.Token, "127.0.0.1")
		if response.Code != http.StatusBadRequest || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE_QUERY")) {
			t.Fatal("malformed or ambiguous history page query was accepted")
		}
	}
	for _, body := range []string{"", "null", "[]", `{"path":"PRIVATE_BODY"}`, "{} {}"} {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/system/history/inventory", strings.NewReader(body))
		r.Header.Set("X-AccessWeaver-Token", s.Token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || bytes.Contains(w.Body.Bytes(), []byte("PRIVATE_BODY")) {
			t.Fatal("capture accepted something other than one empty JSON object")
		}
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid history requests created storage")
	}
}

func TestHistoryBrowserAuthenticationAndProfileAuditRemainMandatory(t *testing.T) {
	paths := []struct{ method, path string }{{"POST", "/api/v1/system/history/inventory"}, {"GET", "/api/v1/system/history/page"}, {"GET", "/api/v1/system/history/records/abc?revision=" + strings.Repeat("a", 64)}, {"GET", "/api/v1/system/history/records/abc/export?revision=" + strings.Repeat("a", 64)}}
	for _, route := range paths {
		for _, boundary := range []string{"token", "host", "origin", "fetch"} {
			s := makeServer(t)
			r := httptest.NewRequest(route.method, "http://127.0.0.1"+route.path, strings.NewReader("{}"))
			r.Header.Set("X-AccessWeaver-Token", s.Token)
			switch boundary {
			case "token":
				r.Header.Set("X-AccessWeaver-Token", "wrong")
			case "host":
				r.Host = "unrelated.invalid"
			case "origin":
				r.Header.Set("Origin", "http://unrelated.invalid")
			case "fetch":
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatal("history browser bypassed a session or browser boundary")
			}
		}
		s, journal, _ := auditedAPIFixture(t)
		response := request(t, s, route.method, route.path, map[string]any{}, s.Token, "127.0.0.1")
		if response.Code != http.StatusForbidden || journal.calls != 0 {
			t.Fatal("profile-only audited session gained a history browser capability")
		}
	}
}

func TestHistoryBrowserCaptureAdmissionKeepsControlsAvailable(t *testing.T) {
	s := historyBrowserFixture(t, map[string][]byte{"record.json": []byte(`{"id":"x","state":"succeeded"}`)})
	held := &heldHistoryResponse{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(held.release) }) }
	done := make(chan struct{})
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("held history capture response did not join")
		}
	})
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/system/history/inventory", strings.NewReader("{}"))
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	go func() { defer close(done); s.Handler().ServeHTTP(held, r) }()
	select {
	case <-held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("capture did not reach its held response")
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := request(t, s, method, "/api/v1/system/history/page", nil, s.Token, "127.0.0.1")
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
			t.Fatal("slow capture response released heavy history admission early")
		}
	}
	for _, route := range []struct{ method, path string }{{"GET", "/api/v1/system"}, {"POST", "/api/v1/system/cancel"}, {"GET", "/api/bootstrap"}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		control := httptest.NewRequest(route.method, "http://127.0.0.1"+route.path, nil).WithContext(ctx)
		control.Header.Set("X-AccessWeaver-Token", s.Token)
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, control)
		cancel()
		if response.Code != http.StatusOK {
			t.Fatal("inventory capture blocked independent status or cancellation")
		}
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("capture response did not drain")
	}
	if held.Code != http.StatusOK {
		t.Fatal("explicit inventory capture failed after release")
	}
	historyBrowserPage(t, s, "")
}

func TestHistoryBrowserErrorsAreFixedAndStreamingIsBounded(t *testing.T) {
	for _, item := range []struct {
		err    error
		status int
	}{{workflow.ErrHistoryInvalidRequest, 400}, {workflow.ErrHistoryInventoryNeeded, 409}, {workflow.ErrHistoryInventoryStale, 409}, {workflow.ErrHistoryRecordUnavailable, 404}, {workflow.ErrHistoryCapacity, 413}, {workflow.ErrHistoryStagingPending, 409}, {workflow.ErrWorkflowBusy, 503}, {workflow.ErrHistoryUnavailable, 500}, {context.Canceled, 408}, {errors.New("PRIVATE_HISTORY_PATH"), 500}} {
		w := httptest.NewRecorder()
		failHistoryBrowser(w, errors.Join(item.err, errors.New("PRIVATE_HISTORY_NATIVE_ERROR")))
		if w.Code != item.status || bytes.Contains(w.Body.Bytes(), []byte("PRIVATE_HISTORY_")) {
			t.Fatal("history error mapping exposed a private cause or incorrect category")
		}
	}
	data := []byte(`{"id":"large","action":"discover","state":"failed","result":"` + strings.Repeat("<", 256<<10) + `"}`)
	s := historyBrowserFixture(t, map[string][]byte{"large.json": data})
	historyBrowserCapture(t, s)
	item := historyBrowserFind(t, historyBrowserPage(t, s, ""), historyBrowserSHA(data))
	path := "/api/v1/system/history/records/" + item.RecordRef
	for _, suffix := range []string{"?revision=" + item.Revision, "/export?revision=" + item.Revision} {
		w := &sizedWorkflowResponse{ResponseRecorder: httptest.NewRecorder()}
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path+suffix, nil)
		r.Header.Set("X-AccessWeaver-Token", s.Token)
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.largest > 32<<10 || w.Body.Len() > len(data)+4096 {
			t.Fatal("selected record response expanded or wrote an aggregate buffer")
		}
		func() {
			defer func() {
				if recover() != http.ErrAbortHandler {
					t.Error("failed selected-record stream was not aborted")
				}
			}()
			s.Handler().ServeHTTP(failedHistoryResponse{httptest.NewRecorder()}, r.Clone(context.Background()))
		}()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ended := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path+"/export?revision="+item.Revision, nil).WithContext(ctx)
	ended.Header.Set("X-AccessWeaver-Token", s.Token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, ended)
	if w.Code != http.StatusRequestTimeout || strings.Contains(w.Header().Get("Content-Type"), "octet-stream") {
		t.Fatal("ended export committed private download framing")
	}
}

var _ io.Writer = historyBrowserWriter{}

type historyBrowserCountingBody struct {
	reader io.Reader
	read   int
}

func (b *historyBrowserCountingBody) Read(data []byte) (int, error) {
	n, err := b.reader.Read(data)
	b.read += n
	return n, err
}
func (*historyBrowserCountingBody) Close() error { return nil }

func TestHistoryBrowserCaptureBodyBoundAndNativeErrorsStayPrivate(t *testing.T) {
	s := makeServer(t)
	missing := filepath.Join(t.TempDir(), "not-created")
	s.Workflows = workflow.NewWithGuard(missing, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	body := &historyBrowserCountingBody{reader: strings.NewReader(`{"ignored":"` + strings.Repeat("x", maxAPIRequestBodyBytes) + `"}`)}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/system/history/inventory", nil)
	r.ContentLength = -1
	r.Body = body
	r.Header.Set("X-AccessWeaver-Token", s.Token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || body.read > maxAPIRequestBodyBytes+1 {
		t.Fatal("inventory exemption bypassed the existing bounded request-body contract")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oversized capture request created inventory storage")
	}
	blockedRoot := filepath.Join(t.TempDir(), "PRIVATE_HISTORY_NATIVE_PATH")
	if err := os.WriteFile(blockedRoot, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Workflows = workflow.NewWithGuard(blockedRoot, managed.NewGuard(func() (*managed.Authority, error) { return nil, nil }))
	response := request(t, s, http.MethodPost, "/api/v1/system/history/inventory", map[string]any{}, s.Token, "127.0.0.1")
	if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE_HISTORY_")) || bytes.Contains(response.Body.Bytes(), []byte(blockedRoot)) {
		t.Fatal("real inventory storage failure exposed a native path or private cause")
	}
	retained, err := os.ReadFile(blockedRoot)
	if err != nil || string(retained) != "retained" {
		t.Fatal("inventory failure repaired or deleted an unrelated source object")
	}
}
