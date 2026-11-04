//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"context"
	"testing"
)

func TestDarwinRemovalReceiptQueriesRejectUncontrolledArgumentsBeforeExecution(t *testing.T) {
	for _, query := range [][2]string{{"--forget", removalCoreReceiptID}, {"--files", "--forget"}, {"--pkg-info", "../../other"}} {
		if _, e := queryRemovalReceipt(context.Background(), query[0], query[1]); e == nil {
			t.Fatal("uncontrolled receipt query accepted")
		}
	}
}
func TestDarwinRemovalMetadataOutputCancelsAtBudgetWithoutRetainingOverflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := removalMetadataOutput{maximum: 4, cancel: cancel}
	if _, e := output.Write([]byte("data")); e != nil {
		t.Fatal(e)
	}
	if _, e := output.Write([]byte("x")); e == nil || ctx.Err() == nil || string(output.data) != "data" {
		t.Fatal("output budget did not cancel and preserve bounded capture", e)
	}
}
