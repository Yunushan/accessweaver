package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const workerReportTestToken = "0123456789abcdef0123456789abcdef0123456789abcdef"

func workerReportFixture(t *testing.T, change func(map[string]any)) json.RawMessage {
	t.Helper()
	envelope := map[string]any{"reportVersion": 1, "resultToken": workerReportTestToken, "ok": true, "data": map[string]any{"retained": true}}
	if change != nil {
		change(envelope)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal("source report fixture could not be encoded")
	}
	return data
}

func TestWorkerReportBindsOnlyTheCurrentLaunch(t *testing.T) {
	original := workerReportFixture(t, nil)
	copyBefore := append([]byte(nil), original...)
	report, err := decodeWorkerReport(original, workerReportTestToken)
	if err != nil || report.failure() != nil || !bytes.Equal(original, copyBefore) {
		t.Fatal("current report was rejected, changed, or classified as failed")
	}
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing-version", func(m map[string]any) { delete(m, "reportVersion") }},
		{"future-version", func(m map[string]any) { m["reportVersion"] = 2 }},
		{"string-version", func(m map[string]any) { m["reportVersion"] = "1" }},
		{"null-version", func(m map[string]any) { m["reportVersion"] = nil }},
		{"missing-token", func(m map[string]any) { delete(m, "resultToken") }},
		{"other-launch", func(m map[string]any) { m["resultToken"] = strings.Repeat("b", 48) }},
		{"short-token", func(m map[string]any) { m["resultToken"] = "PRIVATE_STALE_REPORT" }},
		{"large-token", func(m map[string]any) { m["resultToken"] = strings.Repeat("PRIVATE_STALE_REPORT", 4096) }},
		{"object-token", func(m map[string]any) { m["resultToken"] = map[string]any{"private": "PRIVATE_STALE_REPORT"} }},
		{"null-token", func(m map[string]any) { m["resultToken"] = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeWorkerReport(workerReportFixture(t, tc.change), workerReportTestToken)
			if err == nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), workerReportTestToken) {
				t.Fatal("stale/malformed result was accepted or its data leaked")
			}
		})
	}
	for _, data := range []json.RawMessage{nil, []byte(`null`), []byte(`[]`), []byte(`"PRIVATE_STALE_REPORT"`), []byte(`{"reportVersion":1`)} {
		if _, err := decodeWorkerReport(data, workerReportTestToken); err == nil {
			t.Fatal("non-object or malformed result was bound to a launch")
		}
	}
	for _, token := range []string{"", strings.Repeat("A", 48), strings.Repeat("z", 48), "PRIVATE_EXPECTED_TOKEN"} {
		_, err := decodeWorkerReport(original, token)
		if err == nil || strings.Contains(err.Error(), token) && token != "" {
			t.Fatal("invalid expected correlation token was accepted or exposed")
		}
	}
	// Unrelated private results retained in legacy history are still legal;
	// only the actual executor applies the versioned worker-envelope contract.
	if validateResult(json.RawMessage(`{"legacy":"retained"}`)) != nil {
		t.Fatal("new worker binding changed legacy result validation")
	}
}

func TestWorkerReportRejectsUnknownOrMalformedFailureMarkers(t *testing.T) {
	for _, value := range []any{"", nil, true, 42, []string{"result-too-large"}, "PRIVATE_UNKNOWN_MARKER", strings.Repeat("x", 80)} {
		data := workerReportFixture(t, func(m map[string]any) { m["reportingFailure"] = value })
		report, err := decodeWorkerReport(data, workerReportTestToken)
		if err == nil || report.failure() != nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "PRIVATE_UNKNOWN_MARKER") {
			t.Fatal("unsupported reporting marker was accepted or leaked")
		}
	}
}

func TestWorkerReportFailureIsRetainedAlongsideExecutionAndPersistence(t *testing.T) {
	for _, code := range []string{"result-too-large", "result-serialization", "result-depth", "result-encoding"} {
		t.Run(code, func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			payload := workerReportFixture(t, func(m map[string]any) {
				m["ok"] = false
				m["data"] = nil
				m["reportingFailure"] = code
				m["error"] = "Fixed source reporting failure"
				m["journal"] = "source-journal-retained"
			})
			report, err := decodeWorkerReport(payload, workerReportTestToken)
			if err != nil || !errors.Is(report.failure(), ErrWorkflowResult) {
				t.Fatal("known report failure lost its result category")
			}
			entered := make(chan struct{})
			executionFault := errors.New("PRIVATE_SOURCE_EXECUTION_FAILURE")
			f.manager.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
				observeWorkflowNoNativeOwners(ctx)
				close(entered)
				<-ctx.Done()
				return payload, errors.Join(ctx.Err(), executionFault, report.failure())
			}
			job := f.start()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("source reporting fixture did not execute")
			}
			final := workflowShutdownFinal(t, f.manager)
			if !errors.Is(final, ErrWorkflowExecution) || !errors.Is(final, ErrWorkflowResult) || !errors.Is(final, executionFault) {
				t.Fatal("shutdown lost execution or result reporting cofailure")
			}
			workflowShutdownPublic(t, final, executionFault.Error(), workerReportTestToken)
			got := f.manager.Snapshot()
			if got.State != "failed" || got.FinishedAt.IsZero() || !bytes.Equal(got.Result, payload) {
				t.Fatal("bounded reporting evidence was discarded or published as success")
			}
			if exact := f.manager.TerminalError(job.ID); exact != final {
				t.Fatal("exact completed generation did not retain the same reporting failure")
			}
			history, historyErr := f.manager.History()
			if historyErr != nil || len(history) != 1 || !bytes.Equal(history[0].Result, payload) {
				t.Fatal("terminal persistence lost bounded reporting/recovery evidence")
			}
		})
	}
}

func TestWorkerReportFinalizationMarkersAreClosedAndTyped(t *testing.T) {
	codes := []string{"journal-save", "mutex-release", "mutex-dispose", "uninstaller-start"}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			data := workerReportFixture(t, func(m map[string]any) {
				m["finalizationFailures"] = []string{code}
				m["externalEffectsPending"] = true
			})
			before := append([]byte(nil), data...)
			report, err := decodeWorkerReport(data, workerReportTestToken)
			if err != nil || !report.externalEffectsPending || len(report.finalizationFailures) != 1 || report.finalizationFailures[0] != code || !bytes.Equal(data, before) {
				t.Fatal("known finalization marker was rejected, changed or lost")
			}
			failure := report.failure()
			want := ErrWorkflowCleanup
			if code == "journal-save" {
				want = ErrWorkflowPersistence
			}
			if !errors.Is(failure, want) || errors.Is(failure, ErrWorkflowResult) || errors.Is(failure, ErrWorkflowExecution) || len(failure.Error()) > 128 {
				t.Fatal("finalization marker lost its exact category or exposed an unbounded error")
			}
			if code == "journal-save" && errors.Is(failure, ErrWorkflowCleanup) || code != "journal-save" && errors.Is(failure, ErrWorkflowPersistence) {
				t.Fatal("finalization marker was assigned an unrelated failure category")
			}
		})
	}
	for _, pending := range []bool{false, true} {
		data := workerReportFixture(t, func(m map[string]any) {
			m["finalizationFailures"] = []string{}
			m["externalEffectsPending"] = pending
		})
		report, err := decodeWorkerReport(data, workerReportTestToken)
		if err != nil || report.externalEffectsPending != pending || len(report.finalizationFailures) != 0 || report.failure() != nil {
			t.Fatal("informational external effects state was rejected or invented an execution failure")
		}
	}
}

func TestWorkerReportRejectsMalformedFinalizationMarkersWithoutPrivateOutput(t *testing.T) {
	values := []any{nil, "journal-save", true, false, 42, map[string]any{"PRIVATE": true}, []any{nil}, []any{true}, []string{""}, []string{"PRIVATE_FINALIZATION_DETAIL"}, []string{"Journal-Save"}, []string{"journal-save", "journal-save"}, []string{"journal-save", "mutex-release", "mutex-dispose", "uninstaller-start", "journal-save"}, []string{strings.Repeat("PRIVATE_FINALIZATION_DETAIL", 100)}}
	for index, value := range values {
		t.Run(fmt.Sprintf("finalization-%d", index), func(t *testing.T) {
			report, err := decodeWorkerReport(workerReportFixture(t, func(m map[string]any) {
				m["reportingFailure"] = "result-too-large"
				m["externalEffectsPending"] = true
				m["finalizationFailures"] = value
			}), workerReportTestToken)
			if !errors.Is(err, ErrWorkflowResult) || err.Error() != "workflow result finalization marker is invalid" || report.reportingFailure != "" || len(report.finalizationFailures) != 0 || report.externalEffectsPending || report.failure() != nil {
				t.Fatal("malformed finalization marker was accepted, leaked or returned usable partial metadata")
			}
		})
	}
	for index, value := range []any{nil, "true", "PRIVATE_EXTERNAL_STATE", 0, 1, []bool{}, map[string]bool{"pending": true}} {
		t.Run(fmt.Sprintf("external-%d", index), func(t *testing.T) {
			report, err := decodeWorkerReport(workerReportFixture(t, func(m map[string]any) {
				m["reportingFailure"] = "result-depth"
				m["finalizationFailures"] = []string{"journal-save"}
				m["externalEffectsPending"] = value
			}), workerReportTestToken)
			if !errors.Is(err, ErrWorkflowResult) || err.Error() != "workflow result finalization marker is invalid" || report.reportingFailure != "" || len(report.finalizationFailures) != 0 || report.externalEffectsPending || report.failure() != nil {
				t.Fatal("malformed external effects flag was accepted, leaked or retained partial failure metadata")
			}
		})
	}
}

func TestWorkerReportRejectsDuplicateAndCaseAliasedFinalizationFields(t *testing.T) {
	prefix := fmt.Sprintf(`{"reportVersion":1,"resultToken":%q,`, workerReportTestToken)
	for index, fields := range []string{
		`"finalizationFailures":["mutex-release"],"finalizationFailures":[]`,
		`"finalizationFailures":["mutex-release"],"FinalizationFailures":[]`,
		`"FinalizationFailures":["mutex-release"]`,
		`"finalizationFailures":[],"\u0066inalizationFailures":["mutex-release"]`,
		`"externalEffectsPending":true,"externalEffectsPending":false`,
		`"externalEffectsPending":true,"ExternalEffectsPending":false`,
		`"ExternalEffectsPending":true`,
		`"externalEffectsPending":false,"\u0065xternalEffectsPending":true`,
	} {
		t.Run(fmt.Sprintf("framing-%d", index), func(t *testing.T) {
			report, err := decodeWorkerReport(json.RawMessage(prefix+fields+`}`), workerReportTestToken)
			if !errors.Is(err, ErrWorkflowResult) || err.Error() != "workflow result finalization marker is invalid" || report.externalEffectsPending || len(report.finalizationFailures) != 0 || report.failure() != nil {
				t.Fatal("duplicate or case-aliased finalization field suppressed a failure or exposed partial metadata")
			}
		})
	}
	// These names inside the retained vendor payload are not top-level protocol
	// fields. A framing check must not traverse them as closure metadata.
	data := workerReportFixture(t, func(m map[string]any) {
		m["finalizationFailures"] = []string{}
		m["externalEffectsPending"] = false
		m["data"] = map[string]any{"finalizationFailures": "PRIVATE_VENDOR_DETAIL", "ExternalEffectsPending": true}
	})
	report, err := decodeWorkerReport(data, workerReportTestToken)
	if err != nil || report.failure() != nil || report.externalEffectsPending {
		t.Fatal("nested private payload fields were treated as top-level finalization markers")
	}
}
func TestWorkerReportFinalizationCofailuresSurviveCancellationAndTerminalPersistence(t *testing.T) {
	for _, terminalWriteFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminal-write-fails-%t", terminalWriteFails), func(t *testing.T) {
			f := newWorkflowShutdownFixture(t)
			payload := workerReportFixture(t, func(m map[string]any) {
				m["ok"] = false
				m["data"] = nil
				m["error"] = "Fixed source finalization failure"
				m["reportingFailure"] = "result-too-large"
				m["finalizationFailures"] = []string{"journal-save", "mutex-release", "mutex-dispose", "uninstaller-start"}
				m["externalEffectsPending"] = true
				m["journal"] = "source-recovery-evidence-retained"
			})
			report, err := decodeWorkerReport(payload, workerReportTestToken)
			if err != nil || !report.externalEffectsPending || len(report.finalizationFailures) != 4 {
				t.Fatal("combined finalization source report could not be decoded")
			}
			entered := make(chan struct{})
			executionFault := errors.New("PRIVATE_FINALIZATION_EXECUTION_FAILURE")
			storageFault := errors.New("PRIVATE_FINALIZATION_PERSISTENCE_FAILURE")
			realPersist := f.manager.persist
			terminalWrites := 0
			f.manager.persist = func(path string, data []byte) error {
				var job Job
				if json.Unmarshal(data, &job) != nil {
					return errors.New("source finalization persistence fixture could not decode record")
				}
				if job.State != "running" {
					terminalWrites++
					if terminalWriteFails {
						return storageFault
					}
				}
				return realPersist(path, data)
			}
			f.manager.execute = func(ctx context.Context, _ string, _ Request) (json.RawMessage, error) {
				observeWorkflowNoNativeOwners(ctx)
				close(entered)
				<-ctx.Done()
				return payload, errors.Join(ctx.Err(), executionFault, report.failure())
			}
			job := f.start()
			workflowShutdownAwait(t, entered, "source finalization execution did not start")
			final := workflowShutdownFinal(t, f.manager)
			for _, cause := range []error{context.Canceled, executionFault, ErrWorkflowExecution, ErrWorkflowResult, ErrWorkflowPersistence, ErrWorkflowCleanup} {
				if !errors.Is(final, cause) {
					t.Fatal("cancellation or another failure masked a finalization category")
				}
			}
			if errors.Is(final, storageFault) != terminalWriteFails || terminalWrites != 1 {
				t.Fatal("terminal persistence outcome was lost or retried")
			}
			for _, category := range []error{ErrWorkflowResult, ErrWorkflowPersistence, ErrWorkflowCleanup} {
				if strings.Count(final.Error(), category.Error()) != 1 {
					t.Fatal("public finalization outcome omitted or repeated a fixed failure category")
				}
			}
			workflowShutdownPublic(t, final, executionFault.Error(), storageFault.Error(), workerReportTestToken, "source-recovery-evidence-retained")
			got := f.manager.Snapshot()
			if got.State != "failed" || got.FinishedAt.IsZero() || !bytes.Equal(got.Result, payload) || f.manager.TerminalError(job.ID) != final {
				t.Fatal("completed finalization evidence was discarded or represented as success")
			}
			history, historyErr := f.manager.History()
			if historyErr != nil || len(history) != 1 {
				t.Fatal("finalization source fixture lost its durable record")
			}
			if !terminalWriteFails && !bytes.Equal(history[0].Result, payload) || terminalWriteFails && len(history[0].Result) != 0 {
				t.Fatal("terminal persistence failure invented a durable final result or discarded a successful write")
			}
		})
	}
}
func FuzzWorkerReportEnvelope(f *testing.F) {
	f.Add([]byte(fmt.Sprintf(`{"reportVersion":1,"resultToken":%q,"ok":true}`, workerReportTestToken)))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"reportVersion":1,"resultToken":"stale"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		before := append([]byte(nil), data...)
		report, err := decodeWorkerReport(data, workerReportTestToken)
		if !bytes.Equal(before, data) {
			t.Fatal("report decoder changed caller evidence")
		}
		if err != nil && len(err.Error()) > 128 {
			t.Fatal("report decoder exposed unbounded private input")
		}
		if (report.reportingFailure != "" || len(report.finalizationFailures) != 0 || report.externalEffectsPending) && err != nil {
			t.Fatal("invalid report produced usable reporting metadata")
		}
	})
}
