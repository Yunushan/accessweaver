package engine

import "errors"

var ErrPreparationCleanupUncertain = errors.New("engine preparation cleanup is unconfirmed; restart the controller before another launch")

// Only the category is public. Retain the original causes and the exact owner,
// without retrying an ambiguous numeric-handle close or inventing a child Run.
type processPreparationFailure struct {
	category error
	cause    error
	retained any
}

func (e *processPreparationFailure) Error() string   { return e.category.Error() }
func (e *processPreparationFailure) Unwrap() []error { return []error{e.category, e.cause} }

func preparationCleanupFailure(primary, cleanup error, owner any) error {
	if cleanup == nil {
		return primary
	}
	return &processPreparationFailure{category: ErrPreparationCleanupUncertain, cause: errors.Join(primary, cleanup), retained: owner}
}

func (m *Manager) rememberPreparationFailure(err error) error {
	if !errors.Is(err, ErrPreparationCleanupUncertain) {
		return err
	}
	m.mu.Lock()
	if m.preparationFault == nil {
		m.preparationFault = err
	}
	m.state.State = "error"
	m.state.LastError = ErrPreparationCleanupUncertain.Error()
	m.state.PID = 0
	// There is no started child or in-flight operation to wait on. Stop/Shutdown
	// return this retained fault; process exit owns remaining kernel reclamation.
	m.state.LifecyclePending = false
	m.state.PreparationRestartRequired = true
	failure := m.preparationFault
	m.mu.Unlock()
	return failure
}

func (m *Manager) abortPreparedOwner(owner processLifetime, primary error) error {
	cleanup := owner.abortStart()
	return m.rememberPreparationFailure(preparationCleanupFailure(primary, cleanup, owner))
}
