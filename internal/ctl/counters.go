package ctl

import (
	"sort"
	"strings"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// counterLabels da o nome, em portugues, dos contadores de modulo conhecidos (chaves de
// StatusModulo.contadores, documentadas em ipc.proto), na ordem em que sao exibidos.
var counterLabels = []struct{ key, label string }{
	{"perda.kernel", "Perdas no kernel"},
	{"perda.interface", "Perdas na interface"},
	{"perda.fila_captura", "Perdas na fila de captura"},
	{"perda.fila_eventos", "Perdas na fila de eventos"},
	{"perda.ipc", "Perdas no envio ao Core"},
	{"decode.malformado", "Quadros malformados"},
	{"decode.nao_suportado", "Quadros de protocolo não suportado"},
	{"ip.fragmento", "Fragmentos IP"},
	{"politica.filtrados", "Pacotes fora da política de emissão"},
	{"remontagem.descartados", "ClientHellos fragmentados descartados"},
}

// lossPrefix marca os contadores que sao perdas de dados (os demais descrevem o trafego).
const lossPrefix = "perda."

// Counter e um contador de modulo com o nome para exibir.
type Counter struct {
	Key   string
	Label string
	Value uint64
}

// CounterLabel e o nome para exibir de uma chave de contador; uma chave desconhecida (de um
// modulo mais novo que o Core) aparece pelo proprio nome.
func CounterLabel(key string) string {
	for _, c := range counterLabels {
		if c.key == key {
			return c.label
		}
	}
	return key
}

// ModuleCounters lista os contadores do status: os conhecidos na ordem do catalogo, depois
// os desconhecidos em ordem alfabetica. Sem status ou sem contadores, devolve nil.
func ModuleCounters(st *psychoscopev1.StatusModulo) []Counter {
	have := st.GetContadores()
	if len(have) == 0 {
		return nil
	}
	var out []Counter
	for _, c := range counterLabels {
		if v, ok := have[c.key]; ok {
			out = append(out, Counter{c.key, c.label, v})
		}
	}
	var unknown []string
	for k := range have {
		if CounterLabel(k) == k {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		out = append(out, Counter{k, k, have[k]})
	}
	return out
}

// Losses lista so as perdas que ja aconteceram (valor maior que zero).
func Losses(st *psychoscopev1.StatusModulo) []Counter {
	var out []Counter
	for _, c := range ModuleCounters(st) {
		if strings.HasPrefix(c.Key, lossPrefix) && c.Value > 0 {
			out = append(out, c)
		}
	}
	return out
}
