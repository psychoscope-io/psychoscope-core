package rules

import (
	"context"
	"fmt"
	"testing"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

const benchEvents = 100_000

// benchTraffic gera n eventos com clientes distintos, a 10 us um do outro no tempo dos eventos (a
// janela guarda todos), sem nenhum que alerte: o custo medido e o de avaliar as regras.
//   - "dns": so consultas DNS de 1000 clientes a 64 nomes;
//   - "misto": 50% DNS, 40% handshakes TCP (SYN e SYN-ACK) e 10% ClientHello, de 5000 clientes.
func benchTraffic(kind string, n int) []*psychoscopev1.EventoFluxoRede {
	evs := make([]*psychoscopev1.EventoFluxoRede, 0, n)
	for i := 0; i < n; i++ {
		sec := float64(i) * 10e-6
		switch {
		case kind == "dns" || i%10 < 5:
			evs = append(evs, dnsQuery(sec, fmt.Sprintf("10.1.%d.%d", i%1000/250, i%250+1), fmt.Sprintf("h%d.bench.example.com", i%64)))
		case i%10 < 9:
			client, server := fmt.Sprintf("10.2.%d.%d", i%5000/250, i%250+1), fmt.Sprintf("203.0.113.%d", i%200+1)
			if i%2 == 0 {
				evs = append(evs, syn(sec, client, server, 443))
			} else {
				evs = append(evs, synAck(sec, server, client, 443))
			}
		default:
			evs = append(evs, tlsHello(sec, fmt.Sprintf("10.2.%d.%d", i%5000/250, i%250+1), "203.0.113.9", fmt.Sprintf("site%d.example.com", i%32), "TLS1.3"))
		}
	}
	return evs
}

type benchPub struct{ n int }

func (p *benchPub) Publish(*psychoscopev1.Alerta) { p.n++ }

// BenchmarkEngine mede o motor sozinho (janela + as oito regras, em uma goroutine), sem IPC nem
// desserializacao: eventos ja na fila, como o run() dos testes. O resultado (ev/s) e o teto do
// motor, para comparar com a vazao ponta a ponta do bench_live do sensor.
func BenchmarkEngine(b *testing.B) {
	for _, kind := range []string{"dns", "misto"} {
		b.Run(kind, func(b *testing.B) {
			evs := benchTraffic(kind, benchEvents)
			var alerts int
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				cfg := Default()
				rs, err := Build(cfg)
				if err != nil {
					b.Fatal(err)
				}
				pub := &benchPub{}
				e := detection.NewEngine(detection.EngineConfig{Window: cfg.LongestWindow(), QueueSize: len(evs) + 1}, rs, pub)
				for _, ev := range evs {
					e.Submit("mod-net-sensor", ev)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Run esvazia a fila e volta
				b.StartTimer()
				e.Run(ctx)
				alerts = pub.n
			}
			b.ReportMetric(float64(len(evs))*float64(b.N)/b.Elapsed().Seconds(), "ev/s")
			b.ReportMetric(float64(alerts), "alertas")
		})
	}
}
