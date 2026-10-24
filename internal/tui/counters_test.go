package tui

import (
	"strings"
	"testing"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func TestModulesPanelShowsLossesOfTheSelectedModule(t *testing.T) {
	ms := mods()
	ms[0].UltimoStatus.Contadores = map[string]uint64{
		"perda.kernel": 12, "perda.fila_captura": 3, "perda.ipc": 0, "decode.malformado": 99,
	}
	ms[1].UltimoStatus = &psychoscopev1.StatusModulo{Contadores: map[string]uint64{"perda.kernel": 7}}
	m := NewModel(&fakeBackend{mods: ms})
	feed(m, exec(m.fetchModules())...)

	v := plain(m)
	if !strings.Contains(v, "Perdas no kernel: 12 · Perdas na fila de captura: 3") {
		t.Fatalf("faltou a linha de perdas do modulo selecionado:\n%s", v)
	}
	for _, not := range []string{"Perdas no envio ao Core", "malformados", "perda.kernel"} {
		if strings.Contains(v, not) {
			t.Errorf("a linha so lista perdas que aconteceram, pelo nome legivel: achou %q", not)
		}
	}
	if strings.Count(v, "Perdas no kernel") != 1 {
		t.Errorf("o modulo nao selecionado nao mostra a linha:\n%s", v)
	}

	feed(m, exec2(m, key("down"))...)
	if v := plain(m); !strings.Contains(v, "Perdas no kernel: 7") || strings.Contains(v, ": 12") {
		t.Fatalf("a linha acompanha a selecao:\n%s", v)
	}
}

func TestModulesPanelHasNoLossLineWithoutLosses(t *testing.T) {
	ms := mods()
	ms[0].UltimoStatus.Contadores = map[string]uint64{"perda.kernel": 0, "decode.malformado": 5}
	m := NewModel(&fakeBackend{mods: ms})
	feed(m, exec(m.fetchModules())...)
	if v := plain(m); strings.Contains(v, "Perdas") {
		t.Fatalf("sem perdas nao ha linha:\n%s", v)
	}
}
