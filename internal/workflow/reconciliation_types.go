package workflow

import (
	"errors"
	"time"
)

var (
	ErrLifecycleReconciliationInvalidRequest = errors.New("invalid workflow reconciliation request")
	ErrLifecycleReconciliationUnavailable    = errors.New("positive local ownership proof is unavailable")
	ErrLifecycleReconciliationConflict       = errors.New("workflow reconciliation evidence changed; review again")
	ErrLifecycleReconciliationExpired        = errors.New("workflow reconciliation plan expired; review again")
	ErrLifecycleReconciliationPending        = errors.New("workflow reconciliation is incomplete; preserve its evidence")
)

type LifecycleReconciliationRequest struct {
	Generation  string `json:"generation,omitempty"`
	OperationID string `json:"operationId,omitempty"`
}
type LifecycleReconciliationObject struct {
	Ref    string `json:"ref"`
	Role   string `json:"role"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type LifecycleReconciliationPlan struct {
	ID             string                          `json:"id"`
	ReviewRevision string                          `json:"reviewRevision"`
	OperationID    string                          `json:"operationId"`
	Generation     string                          `json:"generation"`
	Action         string                          `json:"action"`
	ExpiresAt      time.Time                       `json:"expiresAt"`
	IntentSHA256   string                          `json:"intentSHA256"`
	SealSHA256     string                          `json:"sealSHA256"`
	Objects        []LifecycleReconciliationObject `json:"objects"`
	Resume         bool                            `json:"resume"`
	Scope          string                          `json:"scope"`
	Protection     string                          `json:"protection"`
}
type LifecycleReconciliationReceipt struct {
	OperationID  string                          `json:"operationId"`
	Generation   string                          `json:"generation"`
	State        string                          `json:"state"`
	Action       string                          `json:"action"`
	IntentSHA256 string                          `json:"intentSHA256"`
	SealSHA256   string                          `json:"sealSHA256"`
	AckSHA256    string                          `json:"ackSHA256"`
	Quarantined  []LifecycleReconciliationObject `json:"quarantined"`
	CompletedAt  time.Time                       `json:"completedAt"`
	Scope        string                          `json:"scope"`
	Protection   string                          `json:"protection"`
}
type LifecycleReconciliationStatus struct {
	State           string `json:"state"`
	Generation      string `json:"generation,omitempty"`
	OperationID     string `json:"operationId,omitempty"`
	CanPreview      bool   `json:"canPreview"`
	ResumeAvailable bool   `json:"resumeAvailable"`
	Scope           string `json:"scope"`
	Protection      string `json:"protection"`
}

const reconciliationAction = "retry-local-release-ack"
const reconciliationScope = "original-local-owners-only"
const reconciliationProtection = "retirement-unavailable"
