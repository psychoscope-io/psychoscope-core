package store

import (
	"context"
	"fmt"
	"testing"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// BenchmarkInsert mede a gravacao de alertas por tamanho de lote (uma transacao por lote): e o
// teto de vazao do gravador. Reporta alertas/s.
func BenchmarkInsert(b *testing.B) {
	for _, batch := range []int{64, 256, 1024} {
		b.Run(fmt.Sprint(batch), func(b *testing.B) {
			s, err := Open(b.TempDir() + "/alerts.db")
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			lote := make([]*psychoscopev1.Alerta, batch)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := range lote {
					lote[j] = alert(fmt.Sprintf("i%d-%d", i, j), "net.dns.nxdomain_burst", 2, "mod-net-sensor", t0)
				}
				if err := s.Insert(context.Background(), lote); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(batch)*float64(b.N)/b.Elapsed().Seconds(), "alertas/s")
		})
	}
}
