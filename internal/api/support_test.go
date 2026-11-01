package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

func TestSupportReportExcludesPrivateProfileFieldsAndReferencedFiles(t *testing.T) {
	s := makeServer(t)
	marker := "PRIVATE_SUPPORT_FIXTURE"
	config := filepath.Join(t.TempDir(), marker+".conf")
	if err := os.WriteFile(config, []byte(marker+" key material"), 0600); err != nil {
		t.Fatal(err)
	}
	p := profile.Builtins()[0]
	p.ID = "private-support-fixture"
	p.Name = marker
	p.Description = marker
	p.Notes = marker
	p.Args = []string{marker}
	p.ConfigPath = config
	p.Routing.IncludeDomains = []string{"private-support-fixture.example"}
	if err := s.Store.Save(p); err != nil {
		t.Fatal(err)
	}
	response := request(t, s, "GET", "/api/v1/support", nil, s.Token, "127.0.0.1:54321")
	if response.Code != 200 {
		t.Fatalf("support response: %d %s", response.Code, response.Body.String())
	}
	for _, private := range []string{marker, p.ID, s.Token, config, p.Routing.IncludeDomains[0]} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatalf("support export contains private value %q", private)
		}
	}
	var report supportReport
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.Scope != "metadata-only" || (report.Profiles.Total == nil || *report.Profiles.Total != 1 || report.Profiles.Status != "available") || report.Profiles.ByEngine[p.Engine] != 1 || report.Build.Platform == "" || report.Workflow.State != "idle" {
		t.Fatalf("invalid metadata summary: %+v", report)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private support metadata is cacheable")
	}
}

func TestSupportLabelsCannotExportUnknownUserStrings(t *testing.T) {
	marker := "PRIVATE_SUPPORT_LABEL"
	report := newSupportReport([]profile.Profile{{Engine: "byedpi"}, {Engine: marker}}, true, engine.Summary{Engine: marker, State: marker, ErrorPresent: true, LogLines: 3}, workflow.Summary{Action: marker, State: marker, ErrorPresent: true, ResultPresent: true})
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), marker) {
		t.Fatal("unrecognized user string entered metadata")
	}
	if report.Profiles.ByEngine["byedpi"] != 1 || report.Profiles.ByEngine["other"] != 1 || report.Runtime.State != "unknown" || report.Runtime.Engine != "other" || report.Workflow.Action != "other" || !report.Workflow.ErrorPresent {
		t.Fatalf("normalization dropped useful metadata: %+v", report)
	}
}

func TestUnreadableProfileStoreReportsUnknownCountsWithoutPrivateErrors(t *testing.T) {
	s := makeServer(t)
	if err := os.WriteFile(filepath.Join(s.Store.Root, "profiles", "corrupt-fixture.json"), []byte(`{"incomplete":`), 0600); err != nil {
		t.Fatal(err)
	}
	response := request(t, s, "GET", "/api/v1/support", nil, s.Token, "127.0.0.1:54321")
	if response.Code != 200 {
		t.Fatalf("support summary failed for corrupt storage: %d", response.Code)
	}
	var report supportReport
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Profiles.Total != nil || report.Profiles.Status != "unavailable" || len(report.Profiles.ByEngine) != 0 {
		t.Fatalf("unavailable counts misrepresented: %+v", report.Profiles)
	}
	if strings.Contains(response.Body.String(), "corrupt-fixture") || strings.Contains(response.Body.String(), s.Store.Root) {
		t.Fatal("private storage error entered export")
	}
}
