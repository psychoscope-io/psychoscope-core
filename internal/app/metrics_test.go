package app

import (
	"testing"

	"github.com/psychoscope-io/psychoscope-core/internal/supervisor"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func TestModuleMetricsExportEachCounterByContractKey(t *testing.T) {
	in := supervisor.Info{
		ID:    "mod-net-sensor",
		State: psychoscopev1.EstadoModulo_ESTADO_CONECTADO,
		LastStatus: &psychoscopev1.StatusModulo{
			PacotesDescartados: 15,
			Contadores:         map[string]uint64{"perda.kernel": 12, "decode.malformado": 4},
		},
	}
	got := map[string]float64{}
	for _, m := range moduleMetrics(in) {
		if m.Nome == "psychoscope_module_counter_total" {
			if m.Rotulos["module"] != "mod-net-sensor" {
				t.Fatalf("rotulo module = %q", m.Rotulos["module"])
			}
			got[m.Rotulos["counter"]] = m.Valor
		}
	}
	if len(got) != 2 || got["perda.kernel"] != 12 || got["decode.malformado"] != 4 {
		t.Fatalf("contadores exportados = %v", got)
	}
}

func TestModuleMetricsWithoutCountersExportNone(t *testing.T) {
	in := supervisor.Info{ID: "m", LastStatus: &psychoscopev1.StatusModulo{}}
	for _, m := range moduleMetrics(in) {
		if m.Nome == "psychoscope_module_counter_total" {
			t.Fatalf("modulo antigo (sem contadores) nao exporta %v", m)
		}
	}
}
