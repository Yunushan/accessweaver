package workflow

import (
	"errors"
	"os/exec"
	"strings"
	"sync"
)

// These categories describe the retained local outcome. They do not assert
// vendor rollback, descendant termination or successful external recovery.
var (
	ErrWorkflowAdmission   = errors.New("workflow admission failed")
	ErrWorkflowExecution   = errors.New("workflow execution failed")
	ErrWorkflowResult      = errors.New("workflow result is unavailable")
	ErrWorkflowPersistence = errors.New("workflow outcome could not be persisted")
	ErrWorkflowCleanup     = errors.New("workflow native cleanup is unconfirmed")
)

// ErrWorkflowOutcomeUnavailable reports no completed current generation for an
// exact caller-supplied ID. It never includes that ID or private job details.
var ErrWorkflowOutcomeUnavailable = errors.New("workflow terminal outcome is unavailable")

// A completion belongs to exactly one reservation, including its initial and
// terminal persistence. err is published before done closes; cancellation intent
// is guarded by Manager.mu and is observed before the worker cancels itself.
type workflowCompletion struct {
	done            chan struct{}
	err             error
	cancelRequested bool
}

type workflowShutdown struct{ completion *workflowCompletion }

// Shutdown is newly exposed on local stderr. Its printable error must stay
// fixed and small even when the original private tool cause is many MiB.
// Is/As still reach both the category and the actual cause.
type workflowOutcomeFailure struct{ category, cause error }

func (e *workflowOutcomeFailure) Error() string   { return e.category.Error() }
func (e *workflowOutcomeFailure) Unwrap() []error { return []error{e.category, e.cause} }

func workflowFailure(category, cause error) error {
	if cause == nil {
		return nil
	}
	return &workflowOutcomeFailure{category: category, cause: cause}
}

// The final printable view lists each known phase once, including nested
// cleanup/result warnings. It never stringifies the private underlying tree.
type workflowTerminalFailure struct {
	cause   error
	message string
}

func (e *workflowTerminalFailure) Error() string { return e.message }
func (e *workflowTerminalFailure) Unwrap() error { return e.cause }

func workflowFinalFailure(cause error) error {
	if cause == nil {
		return nil
	}
	var messages []string
	for _, category := range []error{ErrWorkflowAdmission, ErrWorkflowExecution, ErrWorkflowResult, ErrWorkflowPersistence, ErrWorkflowCleanup} {
		if errors.Is(cause, category) {
			messages = append(messages, category.Error())
		}
	}
	// Callers provide at least one phase tag. Keep an unknown private cause
	// bounded even if a future caller omits the required classification.
	if len(messages) == 0 {
		messages = append(messages, ErrWorkflowExecution.Error())
	}
	return &workflowTerminalFailure{cause: cause, message: strings.Join(messages, "; ")}
}

// The private executor's result-stage tag preserves its original message for
// bounded Job.Error and existing local callers. Completion always wraps it in
// workflowOutcomeFailure before it can become a printable Shutdown error.
type workflowPhaseCause struct{ category, cause error }

func (e *workflowPhaseCause) Error() string   { return e.cause.Error() }
func (e *workflowPhaseCause) Unwrap() []error { return []error{e.category, e.cause} }

func workflowCause(category, cause error) error {
	if cause == nil {
		return nil
	}
	return &workflowPhaseCause{category: category, cause: cause}
}

// Cmd.Wait may prefer an ExitError over the error returned by Cmd.Cancel.
// Retain that outcome separately, without changing the configured callback's
// target, return value, timing or native termination behavior.
type commandCancellation struct {
	mu  sync.Mutex
	err error
}

func captureCommandCancellation(cmd *exec.Cmd) *commandCancellation {
	observation := &commandCancellation{}
	cancel := cmd.Cancel
	if cancel != nil {
		cmd.Cancel = func() error {
			err := cancel()
			observation.mu.Lock()
			observation.err = errors.Join(observation.err, err)
			observation.mu.Unlock()
			return err
		}
	}
	return observation
}

func (o *commandCancellation) failure() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return workflowFailure(ErrWorkflowCleanup, o.err)
}
