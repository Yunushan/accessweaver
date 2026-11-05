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
		if report.reportingFailure != "" && err != nil {
			t.Fatal("invalid report produced usable reporting metadata")
		}
	})
}
