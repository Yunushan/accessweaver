package api

import (
	"net/http"
	"time"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/engine"
	"github.com/Yunushan/accessweaver/internal/profile"
	"github.com/Yunushan/accessweaver/internal/workflow"
)

type supportReport struct {
	SchemaVersion int          `json:"schemaVersion"`
	Scope         string       `json:"scope"`
	GeneratedAt   time.Time    `json:"generatedAt"`
	Build         supportBuild `json:"build"`
	Profiles      struct {
		Status   string         `json:"status"`
		Total    *int           `json:"total"`
		ByEngine map[string]int `json:"byEngine,omitempty"`
	} `json:"profiles"`
	Runtime  supportRuntime  `json:"runtime"`
	Workflow supportWorkflow `json:"workflow"`
}

type supportBuild struct {
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	SourceState string `json:"sourceState"`
	BuiltAt     string `json:"builtAt"`
	GoVersion   string `json:"goVersion"`
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
}
type supportRuntime struct {
	State        string `json:"state"`
	Engine       string `json:"engine,omitempty"`
	ErrorPresent bool   `json:"errorPresent"`
	LogLines     int    `json:"logLines"`
}
type supportWorkflow struct {
	State         string `json:"state"`
	Action        string `json:"action,omitempty"`
	ErrorPresent  bool   `json:"errorPresent"`
	ResultPresent bool   `json:"resultPresent"`
}

func (s *Server) support(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.Store.ListContext(r.Context())
	if contextErr := r.Context().Err(); contextErr != nil {
		failProfile(w, contextErr, http.StatusServiceUnavailable)
		return
	}
	JSON(w, http.StatusOK, newSupportReport(profiles, err == nil, s.Manager.Summary(), s.Workflows.Summary()))
}

// Construct a fresh allowlisted object. Do not redact a general snapshot: new
// fields on profiles, job results or logs must never enter exports by default.
func newSupportReport(profiles []profile.Profile, profilesAvailable bool, rt engine.Summary, job workflow.Summary) supportReport {
	build := buildinfo.Current()
	report := supportReport{SchemaVersion: 1, Scope: "metadata-only", GeneratedAt: time.Now().UTC(), Build: supportBuild{Version: build.Version, Commit: build.Commit, SourceState: build.SourceState, BuiltAt: build.BuiltAt, GoVersion: build.GoVersion, Platform: build.Platform, Arch: build.Arch}}
	report.Profiles.Status = "unavailable"
	if profilesAvailable {
		total := len(profiles)
		report.Profiles.Total = &total
		report.Profiles.Status = "available"
		report.Profiles.ByEngine = map[string]int{}
		for _, p := range profiles {
			report.Profiles.ByEngine[supportEngine(p.Engine)]++
		}
	}
	rt.State = supportLabel(rt.State, "stopped", "running", "stopping", "error")
	if rt.Engine != "" {
		rt.Engine = supportEngine(rt.Engine)
	}
	if job.State == "" {
		job.State = "idle"
	} else {
		job.State = supportLabel(job.State, "running", "succeeded", "failed", "interrupted")
	}
	if job.Action != "" {
		known := false
		for _, op := range workflow.Catalog() {
			if op.ID == job.Action {
				known = true
				break
			}
		}
		if !known {
			job.Action = "other"
		}
	}
	report.Runtime = supportRuntime{State: rt.State, Engine: rt.Engine, ErrorPresent: rt.ErrorPresent, LogLines: rt.LogLines}
	report.Workflow = supportWorkflow{State: job.State, Action: job.Action, ErrorPresent: job.ErrorPresent, ResultPresent: job.ResultPresent}
	return report
}
func supportEngine(id string) string {
	if _, err := engine.Lookup(id); err == nil {
		return id
	}
	return "other"
}
func supportLabel(value string, allowed ...string) string {
	for _, label := range allowed {
		if value == label {
			return label
		}
	}
	return "unknown"
}
