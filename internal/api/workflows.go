package api

import (
	"net/http"
	"runtime"

	"github.com/Yunushan/accessweaver/internal/workflow"
)

func (s *Server) workflowRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/system/folder", func(w http.ResponseWriter, r *http.Request) {
		plan, err := s.Workflows.Preview(workflow.Request{Action: "choose-folder"})
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		job, err := s.Workflows.Start(plan.ID)
		if err != nil {
			failProfile(w, err, http.StatusConflict)
			return
		}
		JSON(w, 202, job)
	})
	mux.HandleFunc("GET /api/v1/system/presets", func(w http.ResponseWriter, r *http.Request) {
		items, err := workflow.Presets()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		JSON(w, 200, items)
	})
	mux.HandleFunc("GET /api/v1/system", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, 200, map[string]any{"platform": runtime.GOOS, "operations": workflow.Catalog(), "job": s.Workflows.Snapshot()})
	})
	mux.HandleFunc("GET /api/v1/system/history", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.Workflows.History()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		JSON(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/system/preview", func(w http.ResponseWriter, r *http.Request) {
		var input workflow.Request
		if err := readJSON(w, r, &input); err != nil {
			fail(w, 400, err.Error())
			return
		}
		plan, err := s.Workflows.Preview(input)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		JSON(w, 200, plan)
	})
	mux.HandleFunc("POST /api/v1/system/start", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			PlanID  string `json:"planId"`
			Confirm bool   `json:"confirm"`
		}
		if err := readJSON(w, r, &input); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if !input.Confirm {
			fail(w, 400, "review and confirm the system operation first")
			return
		}
		job, err := s.Workflows.Start(input.PlanID)
		if err != nil {
			failProfile(w, err, http.StatusConflict)
			return
		}
		JSON(w, 202, job)
	})
	mux.HandleFunc("POST /api/v1/system/cancel", func(w http.ResponseWriter, r *http.Request) {
		s.Workflows.Cancel()
		JSON(w, 200, s.Workflows.Snapshot())
	})
}
