package rules

import (
	"fmt"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
)

// BenchmarkBeaconChurn mede o beacon sozinho com muito mais origens distintas do que max_keys
// (padrao 50 000): cada evento novo encontra o mapa cheio e dispara o despejo. E o custo de uma
// varredura em massa ou de uma inundacao de DNS com origens falsificadas.
func BenchmarkBeaconChurn(b *testing.B) {
	const n = 200_000
	evs := make([]*detection.Event, n)
	for i := range evs {
		src := fmt.Sprintf("10.%d.%d.%d", 1+i/62500, i/250%250, i%250+1)
		evs[i] = detection.NewEvent("mod-net-sensor", syn(float64(i)*10e-6, src, "198.51.100.7", 443), time.Now())
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := NewBeacon(Default().Beacon)
		for _, ev := range evs {
			r.Eval(ev, nil)
		}
	}
	b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds(), "ev/s")
}
