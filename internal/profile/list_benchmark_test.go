package profile

import (
	"fmt"
	"runtime"
	"testing"
)

// This synthetic store benchmark starts no engines or native system workflows.
// The four-reader case checks aggregate read cost, not packet throughput.
func BenchmarkList256(b *testing.B) {
	store, err := NewStore(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		if err := store.Save(New(fmt.Sprintf("perf-%04d", i), "Performance fixture", "byedpi")); err != nil {
			b.Fatal(err)
		}
	}
	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rows, err := store.List()
			if err != nil || len(rows) != 256 {
				b.Fatal("inventory failed", err)
			}
		}
	})
	b.Run("four_readers", func(b *testing.B) {
		previous := runtime.GOMAXPROCS(4)
		defer runtime.GOMAXPROCS(previous)
		b.ReportAllocs()
		b.ReportMetric(4, "readers")
		b.RunParallel(func(loop *testing.PB) {
			for loop.Next() {
				rows, err := store.List()
				if err != nil || len(rows) != 256 {
					b.Fatal("inventory failed", err)
				}
			}
		})
	})
}
