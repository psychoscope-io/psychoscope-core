package ctl

import (
	"testing"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func TestModuleCountersOrderAndFallback(t *testing.T) {
	st := &psychoscopev1.StatusModulo{Contadores: map[string]uint64{
		"zeta.novo": 1, "decode.malformado": 4, "perda.kernel": 2, "alfa.novo": 9, "perda.ipc": 0,
	}}
	var keys []string
	for _, c := range ModuleCounters(st) {
		keys = append(keys, c.Key)
	}
	want := []string{"perda.kernel", "perda.ipc", "decode.malformado", "alfa.novo", "zeta.novo"}
	if len(keys) != len(want) {
		t.Fatalf("chaves = %v, quer %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("chaves = %v, quer %v", keys, want)
		}
	}
	if got := CounterLabel("perda.kernel"); got != "Perdas no kernel" {
		t.Fatalf("rotulo = %q", got)
	}
	if got := CounterLabel("zeta.novo"); got != "zeta.novo" {
		t.Fatalf("chave desconhecida deve aparecer pelo nome, veio %q", got)
	}
}

func TestLossesOnlyListsRealLosses(t *testing.T) {
	st := &psychoscopev1.StatusModulo{Contadores: map[string]uint64{
		"perda.kernel": 0, "perda.fila_captura": 3, "decode.malformado": 50,
	}}
	l := Losses(st)
	if len(l) != 1 || l[0].Key != "perda.fila_captura" || l[0].Value != 3 {
		t.Fatalf("perdas = %+v", l)
	}
	if Losses(nil) != nil || ModuleCounters(&psychoscopev1.StatusModulo{}) != nil {
		t.Fatal("sem status ou sem contadores deve devolver nil")
	}
}

func TestPacketsCellShowsDashWhenNoPacketsWereReported(t *testing.T) {
	if got := PacketsCell(nil); got != "-" {
		t.Errorf("sem status: %q", got)
	}
	if got := PacketsCell(&psychoscopev1.StatusModulo{EventosProcessados: 9}); got != "-" {
		t.Errorf("modulo que nao captura pacotes: %q", got)
	}
	if got := PacketsCell(&psychoscopev1.StatusModulo{PacotesCapturados: 1234}); got != "1234" {
		t.Errorf("modulo de rede: %q", got)
	}
}
