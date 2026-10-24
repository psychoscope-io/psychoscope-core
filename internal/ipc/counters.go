package ipc

import (
	"sort"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Limites dos contadores de um StatusModulo. O mapa vem de um modulo (entrada nao confiavel
// para quem consome: viram series de metricas e linhas na TUI), entao o Core o limita na
// fronteira, em vez de cada consumidor se defender sozinho.
const (
	MaxCounters      = 64
	MaxCounterKeyLen = 64
)

// validCounterKey aceita chaves em minusculas com pontos, como "perda.fila_captura".
func validCounterKey(k string) bool {
	if k == "" || len(k) > MaxCounterKeyLen {
		return false
	}
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// limitCounters remove de st.Contadores as chaves invalidas e o que passar de MaxCounters
// (ficam as primeiras em ordem alfabetica, para o resultado nao depender da ordem do mapa) e
// devolve quantas entradas descartou.
func limitCounters(st *psychoscopev1.StatusModulo) int {
	in := st.GetContadores()
	if len(in) == 0 {
		return 0
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		if validCounterKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > MaxCounters {
		keys = keys[:MaxCounters]
	}
	if len(keys) == len(in) {
		return 0
	}
	kept := make(map[string]uint64, len(keys))
	for _, k := range keys {
		kept[k] = in[k]
	}
	st.Contadores = kept
	return len(in) - len(kept)
}
