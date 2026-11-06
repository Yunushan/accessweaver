package api

import (
	"net/http"

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
		workflowJobJSON(w, r, http.StatusAccepted, job)
	})
	mux.HandleFunc("GET /api/v1/system/presets", func(w http.ResponseWriter, r *http.Request) {
		items, err := workflow.Presets()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		JSON(w, 200, items)
	})
	mux.HandleFunc("GET /api/v1/system", s.workflowStatus)
	mux.HandleFunc("GET /api/v1/system/history", s.workflowHistory)
	mux.HandleFunc("POST /api/v1/system/history/inventory", s.workflowHistoryInventory)
	mux.HandleFunc("GET /api/v1/system/history/page", s.workflowHistoryPage)
	mux.HandleFunc("GET /api/v1/system/history/records/{recordRef}", s.workflowHistoryRecord)
	mux.HandleFunc("GET /api/v1/system/history/records/{recordRef}/export", s.workflowHistoryRecordExport)
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
		workflowJobJSON(w, r, http.StatusAccepted, job)
	})
	mux.HandleFunc("POST /api/v1/system/cancel", func(w http.ResponseWriter, r *http.Request) {
		s.Workflows.Cancel()
		workflowJobJSON(w, r, http.StatusOK, s.Workflows.Snapshot())
	})
}
