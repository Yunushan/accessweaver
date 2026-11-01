package main

import (
	"github.com/Yunushan/accessweaver/internal/engine"
	"strings"
	"testing"
	"time"
)

// Called only after explicit native mutation inside the disposable policy tests.
func assertNativePolicyStopped(t *testing.T, manager *engine.Manager, reason string) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && manager.Snapshot().PID != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	state := manager.Snapshot()
	if state.PID != 0 || state.State != "error" || !strings.Contains(state.LastError, reason) {
		t.Fatalf("active native policy change did not terminate/report owned engine: %+v", state)
	}
}
