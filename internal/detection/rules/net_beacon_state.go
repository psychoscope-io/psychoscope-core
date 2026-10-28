package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// maxBeaconKeyLen limita a chave de uma serie restaurada (entrada nao confiavel).
const maxBeaconKeyLen = 512

// beaconState e o estado do beacon que sobrevive a um reinicio ou a um Reconfigure. Todos os
// instantes sao tempo dos eventos, em nanossegundos Unix (8 bytes em vez dos 24 de um time.Time:
// a copia roda na goroutine do motor e, no teto de series, o tamanho dela e o que custa).
type beaconState struct {
	// MinIntervalNs e o min_interval com que as series foram montadas: se mudou, as series
	// deixam de valer (o filtro de rajada era outro) e so os cooldowns sao restaurados.
	MinIntervalNs int64            `json:"min_interval_ns"`
	Series        []beaconSeries   `json:"series,omitempty"`
	Cooldowns     []beaconCooldown `json:"cooldowns,omitempty"`
}

type beaconSeries struct {
	Chave    string  `json:"chave"`
	VistoNs  int64   `json:"visto_ns"`
	Contatos []int64 `json:"contatos_ns"`
}

type beaconCooldown struct {
	Chave    string `json:"chave"`
	AlertaNs int64  `json:"alerta_ns"`
}

// ExportState copia as series ainda uteis em now e so os cooldowns ainda ativos (o mapa pode
// passar de max_keys, porque o despejo de series nao o poda).
func (r *Beacon) ExportState(now time.Time) any {
	st := beaconState{MinIntervalNs: int64(r.cfg.MinInterval)}
	stale := now.Add(-2 * r.cfg.MaxInterval)
	for k, s := range r.series {
		if s.seen.Before(stale) || len(s.times) == 0 {
			continue
		}
		contacts := make([]int64, len(s.times))
		for i, t := range s.times {
			contacts[i] = t.UnixNano()
		}
		st.Series = append(st.Series, beaconSeries{Chave: k, VistoNs: s.seen.UnixNano(), Contatos: contacts})
	}
	for k, last := range r.cooldown {
		if now.Before(last.Add(r.cfg.Cooldown)) {
			st.Cooldowns = append(st.Cooldowns, beaconCooldown{Chave: k, AlertaNs: last.UnixNano()})
		}
	}
	return st
}

// ImportState restaura o estado exportado, validando cada entrada: o que for invalido e
// descartado, as series so valem com o mesmo min_interval e o total e aparado para max_keys
// (ficam as mais recentes). Devolve quantas series e cooldowns ficaram.
func (r *Beacon) ImportState(raw []byte) (int, error) {
	var st beaconState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return 0, fmt.Errorf("estado do beacon ilegivel: %w", err)
	}
	kept := 0
	if st.MinIntervalNs == int64(r.cfg.MinInterval) {
		kept += r.importSeries(st.Series)
	}
	return kept + r.importCooldowns(st.Cooldowns), nil
}

func (r *Beacon) importSeries(in []beaconSeries) int {
	valid := in[:0:0]
	for _, s := range in {
		if validBeaconKey(s.Chave) && validContacts(s.Contatos, s.VistoNs) {
			valid = append(valid, s)
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].VistoNs > valid[j].VistoNs })
	if len(valid) > r.cfg.MaxKeys {
		valid = valid[:r.cfg.MaxKeys]
	}
	for _, s := range valid {
		times := make([]time.Time, len(s.Contatos))
		for i, ns := range s.Contatos {
			times[i] = time.Unix(0, ns)
		}
		r.series[s.Chave] = &series{times: times, seen: time.Unix(0, s.VistoNs)}
	}
	return len(valid)
}

func (r *Beacon) importCooldowns(in []beaconCooldown) int {
	valid := in[:0:0]
	for _, c := range in {
		if validBeaconKey(c.Chave) && c.AlertaNs > 0 {
			valid = append(valid, c)
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].AlertaNs > valid[j].AlertaNs })
	if len(valid) > r.cfg.MaxKeys {
		valid = valid[:r.cfg.MaxKeys]
	}
	for _, c := range valid {
		r.cooldown[c.Chave] = time.Unix(0, c.AlertaNs)
	}
	return len(valid)
}

// validBeaconKey aceita so as chaves que classify produz ("tcp|origem|ip:porta" e "dns|origem|dominio").
func validBeaconKey(k string) bool {
	return len(k) <= maxBeaconKeyLen && (strings.HasPrefix(k, "tcp|") || strings.HasPrefix(k, "dns|"))
}

// validContacts exige de 1 a maxSeriesLen contatos em ordem nao decrescente, sem passar do
// ultimo evento visto: do contrario admit() rejeitaria os proximos eventos da chave.
func validContacts(ts []int64, seen int64) bool {
	if len(ts) == 0 || len(ts) > maxSeriesLen || seen <= 0 || ts[0] <= 0 {
		return false
	}
	for i := 1; i < len(ts); i++ {
		if ts[i] < ts[i-1] {
			return false
		}
	}
	return ts[len(ts)-1] <= seen
}
