package workflow

import (
	"errors"
	"math"
)

var (
	ErrWorkflowStorageCapacity = errors.New("workflow controller evidence exceeds its reserved capacity")
	ErrWorkflowStoragePending  = errors.New("workflow controller storage requires explicit review")
)

const (
	controllerStorageDirectory         = ".workflow-controller-storage"
	controllerStorageCurrent           = ".workflow-controller-storage.current"
	controllerStorageMetadataMax       = 4096
	controllerStorageLogBytes    int64 = 3 * (4 << 20)
	// This is bounded source metadata credit, not a physical-space reservation.
	// It includes intent/seal/ack, replacement pointer/stage peaks and two epochs.
	controllerStorageControlBytes int64 = 2*workflowLifecycleMaxReceiptBytes + 4*controllerStorageMetadataMax + 4*49
)

// ControllerStorageStatus reports commitments for the tracked source protocol.
// Charges are conservative allowances, never a recursive disk-usage inventory.
// An uninitialized status does not assert legacy/untracked storage is empty.
type ControllerStorageStatus struct {
	State                      string `json:"state"`
	Scope                      string `json:"scope"`
	Generation                 string `json:"generation,omitempty"`
	Action                     string `json:"action,omitempty"`
	GenerationsTracked         uint64 `json:"generationsTracked"`
	ReservedBytes              int64  `json:"reservedBytes"`
	RetainedChargeBytes        int64  `json:"retainedChargeBytes"`
	UncertainBytes             int64  `json:"uncertainBytes"`
	FinalizationReservedBytes  int64  `json:"finalizationReservedBytes"`
	LegacyAccounting           string `json:"legacyAccounting"`
	AggregateQuotaEnforced     bool   `json:"aggregateQuotaEnforced"`
	PhysicalCapacityGuaranteed bool   `json:"physicalCapacityGuaranteed"`
	NativeWritersContained     bool   `json:"nativeWritersContained"`
	WorkerJournalBounded       bool   `json:"workerJournalBounded"`
}

type controllerStorageRoles struct {
	ScriptBytes         int64 `json:"scriptBytes"`
	RequestBytes        int64 `json:"requestBytes"`
	InitialRecordBytes  int64 `json:"initialRecordBytes"`
	TerminalRecordBytes int64 `json:"terminalRecordBytes"`
	LogPoolBytes        int64 `json:"logPoolBytes"`
	ReportBytes         int64 `json:"reportBytes"`
	ControlBytes        int64 `json:"controlBytes"`
}

func (p controllerStorageRoles) total() (int64, error) {
	var total int64
	for _, n := range []int64{p.ScriptBytes, p.RequestBytes, p.InitialRecordBytes, p.TerminalRecordBytes, p.LogPoolBytes, p.ReportBytes, p.ControlBytes} {
		if n < 0 || n > math.MaxInt64-total {
			return 0, ErrWorkflowStorageCapacity
		}
		total += n
	}
	return total, nil
}
func controllerStoragePlan(p *preparedWorkflowInput, initial []byte) (controllerStorageRoles, error) {
	roles := controllerStorageRoles{int64(len(p.Script)), int64(len(p.Input)), int64(len(initial)), maxHistoryRecordBytes, controllerStorageLogBytes, maxResultBytes, controllerStorageControlBytes}
	_, err := roles.total()
	return roles, err
}
