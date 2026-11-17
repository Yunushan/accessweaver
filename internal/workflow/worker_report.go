package workflow

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const workerReportVersion = 1

type workerReport struct {
	reportingFailure     string
	finalizationFailures []string
	// Informational only: accepted vendor effects or an unobserved handoff do
	// not prove execution failure, completion, or successful external rollback.
	externalEffectsPending bool
}

// The new closure-related fields have one exact top-level spelling and cannot
// be suppressed by a later duplicate or a case alias. Unknown payload fields
// remain legal and are skipped without constructing their object graph.
func validWorkerFinalizationFields(result json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(result))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok {
			return false
		}
		for _, name := range []string{"finalizationFailures", "externalEffectsPending"} {
			if strings.EqualFold(key, name) {
				if key != name || seen[name] {
					return false
				}
				seen[name] = true
			}
		}
		var discard json.RawMessage
		if decoder.Decode(&discard) != nil {
			return false
		}
	}
	closing, err := decoder.Token()
	return err == nil && closing == json.Delim('}') && decoder.Decode(new(any)) == io.EOF
}

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
		ReportVersion          json.RawMessage `json:"reportVersion"`
		ResultToken            json.RawMessage `json:"resultToken"`
		ReportingFailure       json.RawMessage `json:"reportingFailure"`
		FinalizationFailures   json.RawMessage `json:"finalizationFailures"`
		ExternalEffectsPending json.RawMessage `json:"externalEffectsPending"`
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
	invalidFinalization := func() (workerReport, error) {
		return workerReport{}, workflowCause(ErrWorkflowResult, errors.New("workflow result finalization marker is invalid"))
	}
	if !validWorkerFinalizationFields(result) {
		return invalidFinalization()
	}
	if len(envelope.FinalizationFailures) != 0 {
		if len(envelope.FinalizationFailures) > 256 || bytes.Equal(bytes.TrimSpace(envelope.FinalizationFailures), []byte("null")) || json.Unmarshal(envelope.FinalizationFailures, &report.finalizationFailures) != nil || len(report.finalizationFailures) > 4 {
			return invalidFinalization()
		}
		seen := make(map[string]bool, len(report.finalizationFailures))
		for _, code := range report.finalizationFailures {
			switch code {
			case "journal-save", "mutex-release", "mutex-dispose", "uninstaller-start":
			default:
				return invalidFinalization()
			}
			if seen[code] {
				return invalidFinalization()
			}
			seen[code] = true
		}
	}
	if len(envelope.ExternalEffectsPending) != 0 {
		switch string(bytes.TrimSpace(envelope.ExternalEffectsPending)) {
		case "true":
			report.externalEffectsPending = true
		case "false":
		default:
			return invalidFinalization()
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
	}
	var failures []error
	if message != "" {
		failures = append(failures, workflowCause(ErrWorkflowResult, errors.New(message)))
	}
	for _, code := range report.finalizationFailures {
		var category error
		switch code {
		case "journal-save":
			category = ErrWorkflowPersistence
			message = "workflow recovery journal final save failed"
		case "mutex-release":
			category = ErrWorkflowCleanup
			message = "workflow mutex release is unconfirmed"
		case "mutex-dispose":
			category = ErrWorkflowCleanup
			message = "workflow mutex disposal is unconfirmed"
		case "uninstaller-start":
			category = ErrWorkflowCleanup
			message = "workflow deferred uninstaller start is unconfirmed"
		default:
			continue // Only decoder-approved codes are usable protocol metadata.
		}
		failures = append(failures, workflowCause(category, errors.New(message)))
	}
	return errors.Join(failures...)
}
