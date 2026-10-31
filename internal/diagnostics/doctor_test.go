package diagnostics

import (
	"context"
	"github.com/Yunushan/accessweaver/internal/profile"
	"testing"
)

func TestRejectInvalidInputs(t *testing.T) {
	report := Run(context.Background(), profile.Probe{Host: "example.org;bad", Port: 443})
	if len(report.Checks) != 1 || report.Checks[0].Status != "failed" {
		t.Fatalf("invalid host was not rejected: %+v", report)
	}
}
