package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// analysis e o resultado de uma analise offline, ja sem nenhum I/O: e o que o texto e o JSON
// do relatorio mostram.
type analysis struct {
	File       string
	Events     uint64 // eventos de rede entregues ao motor
	First      time.Time
	Last       time.Time
	Alerts     []*psychoscopev1.Alerta // na ordem em que o motor os produziu
	OverLimit  int                     // alertas descartados por --max-alerts
	RuleFilter string                  // so as linhas desta regra foram mantidas
	Err        string                  // analise incompleta: o que interrompeu a leitura
}

// alertTime e o instante do evento que disparou o alerta (contexto evento_ts), que e
// reproduzivel; o instante da deteccao (Timestamp) e o relogio de quem rodou a analise.
func alertTime(a *psychoscopev1.Alerta) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, a.Contexto["evento_ts"]); err == nil {
		return t.UTC(), true
	}
	if a.Timestamp != nil {
		return a.Timestamp.AsTime().UTC(), false
	}
	return time.Time{}, false
}

// perRule conta os alertas por regra.
func (an *analysis) perRule() map[string]int {
	m := map[string]int{}
	for _, a := range an.Alerts {
		m[a.Regra]++
	}
	return m
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeText imprime os alertas no estilo de `alerts -v` (com o instante do evento, em UTC) e o resumo.
func (an *analysis) writeText(out io.Writer) {
	for _, a := range an.Alerts {
		ts := "----/--/-- --:--:--"
		if t, ok := alertTime(a); ok {
			ts = t.Format("2006-01-02 15:04:05Z")
		}
		fmt.Fprintln(out, formatAlertAt(ts, a, true))
	}
	if len(an.Alerts) > 0 {
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "arquivo: %s\n", an.File)
	if an.Events == 0 {
		fmt.Fprintln(out, "eventos analisados: 0 (o sensor nao extraiu nenhum evento de rede deste arquivo)")
	} else {
		fmt.Fprintf(out, "eventos analisados: %d (de %s a %s, UTC)\n", an.Events,
			an.First.UTC().Format("2006-01-02 15:04:05"), an.Last.UTC().Format("2006-01-02 15:04:05"))
	}
	if len(an.Alerts) == 0 {
		fmt.Fprintln(out, "alertas: nenhum"+an.filterNote())
	} else {
		counts := an.perRule()
		parts := make([]string, 0, len(counts))
		for _, r := range sortedKeys(counts) {
			parts = append(parts, fmt.Sprintf("%s=%d", r, counts[r]))
		}
		fmt.Fprintf(out, "alertas: %d (%s)%s\n", len(an.Alerts), strings.Join(parts, ", "), an.filterNote())
	}
	if an.OverLimit > 0 {
		fmt.Fprintf(out, "aviso: %d alertas a mais foram descartados por --max-alerts\n", an.OverLimit)
	}
	if an.Err != "" {
		fmt.Fprintln(out, "analise INCOMPLETA: "+an.Err)
	}
}

func (an *analysis) filterNote() string {
	if an.RuleFilter == "" {
		return ""
	}
	return " [so a regra " + an.RuleFilter + "]"
}

type jsonAlert struct {
	Instante   string            `json:"instante"`
	Severidade string            `json:"severidade"`
	Regra      string            `json:"regra"`
	Descricao  string            `json:"descricao"`
	Contexto   map[string]string `json:"contexto"`
}

type jsonAnalysis struct {
	Arquivo    string         `json:"arquivo"`
	Eventos    uint64         `json:"eventos"`
	Inicio     string         `json:"inicio,omitempty"`
	Fim        string         `json:"fim,omitempty"`
	Alertas    []jsonAlert    `json:"alertas"`
	PorRegra   map[string]int `json:"por_regra"`
	Descartes  int            `json:"alertas_descartados"`
	Filtro     string         `json:"filtro_regra,omitempty"`
	Incompleta bool           `json:"incompleta"`
	Erro       string         `json:"erro,omitempty"`
}

// writeJSON imprime um unico objeto JSON (chaves em portugues, como o doctor --json).
func (an *analysis) writeJSON(out io.Writer) error {
	j := jsonAnalysis{
		Arquivo: an.File, Eventos: an.Events, Alertas: []jsonAlert{}, PorRegra: an.perRule(),
		Descartes: an.OverLimit, Filtro: an.RuleFilter, Incompleta: an.Err != "", Erro: an.Err,
	}
	if an.Events > 0 {
		j.Inicio, j.Fim = an.First.UTC().Format(time.RFC3339Nano), an.Last.UTC().Format(time.RFC3339Nano)
	}
	for _, a := range an.Alerts {
		ts := ""
		if t, ok := alertTime(a); ok {
			ts = t.Format(time.RFC3339Nano)
		}
		ctx := a.Contexto
		if ctx == nil {
			ctx = map[string]string{}
		}
		j.Alertas = append(j.Alertas, jsonAlert{
			Instante: ts, Severidade: strings.TrimPrefix(a.Severidade.String(), "SEVERIDADE_"),
			Regra: a.Regra, Descricao: a.Descricao, Contexto: ctx,
		})
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(j)
}
