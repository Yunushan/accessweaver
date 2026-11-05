package workflow

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const workerReportVersion = 1

type workerReport struct{ reportingFailure string }

// The nonce correlates a report with this launch. It is not an authentication
// claim about user-writable storage, publisher identity or external OS effects.
// Legacy history is deliberately not subjected to this new worker protocol.
func decodeWorkerReport(result json.RawMessage, expectedToken string) (workerReport, error) {
	invalid := func() (workerReport, error) {
		return workerReport{}, errors.New("workflow result is not bound to this launch")
	}
	if len(expectedToken) != 48 {
		return invalid()
	}
	if token, err := hex.DecodeString(expectedToken); err != nil || len(token) != 24 || hex.EncodeToString(token) != expectedToken {
		return invalid()
	}
	var envelope struct {
		ReportVersion    json.RawMessage `json:"reportVersion"`
		ResultToken      json.RawMessage `json:"resultToken"`
		ReportingFailure json.RawMessage `json:"reportingFailure"`
	}
	if json.Unmarshal(result, &envelope) != nil {
		return invalid()
	}
	var version int
	if json.Unmarshal(envelope.ReportVersion, &version) != nil || version != workerReportVersion || len(envelope.ResultToken) != 50 {
		return invalid()
	}
	var token string
	if json.Unmarshal(envelope.ResultToken, &token) != nil || len(token) != 48 || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
		return invalid()
	}
	var report workerReport
	if len(envelope.ReportingFailure) != 0 {
		if len(envelope.ReportingFailure) > 64 || json.Unmarshal(envelope.ReportingFailure, &report.reportingFailure) != nil {
			return workerReport{}, errors.New("workflow result reporting marker is invalid")
		}
		switch report.reportingFailure {
		case "result-too-large", "result-serialization", "result-depth", "result-encoding":
		default:
			return workerReport{}, errors.New("workflow result reporting marker is invalid")
		}
	}
	return report, nil
}

func (report workerReport) failure() error {
	var message string
	switch report.reportingFailure {
	case "result-too-large":
		message = "workflow result exceeded its writer byte limit"
	case "result-serialization":
		message = "workflow result could not be serialized"
	case "result-depth":
		message = "workflow result exceeded its supported serialization depth"
	case "result-encoding":
		message = "workflow result could not be encoded as UTF-8"
	default:
		return nil
	}
	return workflowCause(ErrWorkflowResult, errors.New(message))
}
