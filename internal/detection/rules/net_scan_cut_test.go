package rules

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// evalWithoutCut e o Eval do ScanSYN sem o corte barato: a referencia contra a qual o corte e comparado.
func evalWithoutCut(r *ScanSYN, ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	p := r.collect(ev, w)
	if dst, n := p.busiestDst(); n >= r.cfg.VerticalPorts {
		return r.verticalAlert(ev, dst, p.portsByDst[dst])
	}
	if port, n := r.busiestUnanswered(ev, w, p, r.cfg.HorizontalHosts); n >= r.cfg.HorizontalHosts {
		return r.horizontalAlert(ev, port, len(p.hostsByPort[port]), n)
	}
	return nil
}

// O corte barato do Eval so pode economizar trabalho: para qualquer trafego (varreduras verticais,
// horizontais, SYN-ACK de respostas e ruido), os alertas sao os mesmos da versao sem o corte.
func TestScanSYNCheapCutKeepsAlerts(t *testing.T) {
	cfg := Default().Scan
	rng := rand.New(rand.NewSource(7))
	r := NewScanSYN(cfg)
	w := detection.NewWindow(time.Minute, 100_000)
	alerts := 0
	for i := 0; i < 20_000; i++ {
		sec := float64(i) * 0.05
		src := fmt.Sprintf("10.0.0.%d", 1+rng.Intn(6))
		var e *psychoscopev1.EventoFluxoRede
		switch k := rng.Intn(10); {
		case k < 5: // varredura vertical: poucas origens, um destino, muitas portas
			e = syn(sec, src, "192.0.2.1", uint32(1+rng.Intn(60)))
		case k < 8: // varredura horizontal: uma porta, muitos destinos
			e = syn(sec, src, fmt.Sprintf("192.0.2.%d", 1+rng.Intn(80)), 22)
		case k < 9: // respostas SYN-ACK dos destinos
			e = synAck(sec, fmt.Sprintf("192.0.2.%d", 1+rng.Intn(80)), src, 22)
		default: // ruido: uma origem so toca poucos destinos
			e = syn(sec, fmt.Sprintf("10.9.%d.%d", rng.Intn(50), rng.Intn(50)), "198.51.100.9", 443)
		}
		ev := detection.NewEvent("m", e, time.Now())
		w.Add(ev)
		got, want := r.Eval(ev, w), evalWithoutCut(r, ev, w)
		if (got == nil) != (want == nil) || (got != nil && got.Descricao != want.Descricao) {
			t.Fatalf("evento %d: com corte %v, sem corte %v", i, got, want)
		}
		if got != nil {
			alerts++
		}
	}
	if alerts < 100 {
		t.Fatalf("o trafego gerou so %d alertas: o teste nao exercita a varredura", alerts)
	}
}
