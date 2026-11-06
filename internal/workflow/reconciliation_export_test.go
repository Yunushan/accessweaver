package workflow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// This factory exists only in the Go test archive. It uses the actual canceled
// pre-execution source branch and physically closed metadata publisher fault;
// no production mode, external backend or caller-created proof is exposed.
func NewReconciliationHTTPFixtureForTest(t *testing.T) (*Manager, string, string) {
	t.Helper()
	fixture, job := workflowReconciliationFixture(t)
	return fixture.manager, fixture.root, job.ID
}

// The incomplete operation already carries actual prior positive release proof.
// Cancel only after that accepted operation reaches its real transaction lease;
// the original tests independently verify that exact durable boundary.
func NewReconciliationResumeHTTPFixtureForTest(t *testing.T) (*Manager, string, string, string) {
	t.Helper()
	fixture, job := workflowReconciliationFixture(t)
	manager := fixture.manager
	plan := workflowReconciliationPlan(t, manager)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.openStoreLease = func(path string) (workflowStoreLease, error) {
		lease, err := openWorkflowStoreLease(path)
		if err == nil && filepath.Base(path) == workflowTransactionLockName {
			cancel()
		}
		return lease, err
	}
	if _, err := manager.ApplyLifecycleReconciliation(ctx, plan.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("source durable resume fixture did not reach accepted canceled operation")
	}
	fresh := workflowLifecycleFreshManager(fixture)
	status, err := fresh.LifecycleReconciliationStatus(context.Background())
	if err != nil || status.State != "pending" || !status.ResumeAvailable {
		t.Fatal("source durable resume fixture lacks legitimate positive proof")
	}
	return fresh, fixture.root, job.ID, plan.OperationID
}
