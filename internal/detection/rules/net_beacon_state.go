package rules

import (
	"bytes"
	"encoding/json"
	"errors"
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

// maxStateEntries limita quantas series (e quantos cooldowns) ExportState entrega, as mais
// recentes: com o tamanho maximo de uma serie em JSON, o arquivo do motor continua abaixo do
// limite de leitura do enginestate mesmo com max_keys alto.
const maxStateEntries = 30_000

// maxImportElements limita quantos elementos de cada lista ImportState examina antes de recusar o estado.
const maxImportElements = 2 * maxStateEntries

// maxContactsJSON e o maior texto JSON aceito para os contatos de uma serie (maxSeriesLen
// numeros de ate 20 digitos com virgula); acima disso o elemento e descartado sem decodificar.
const maxContactsJSON = maxSeriesLen*21 + 2

// ExportState copia as series ainda uteis em now e so os cooldowns ainda ativos (o mapa pode
// passar de max_keys, porque o despejo de series nao o poda), no maximo maxStateEntries de cada.
// Roda na goroutine do motor: nao ordena, a nao ser que passe do teto.
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
	if len(st.Series) > maxStateEntries {
		sort.Slice(st.Series, func(i, j int) bool { return st.Series[i].VistoNs > st.Series[j].VistoNs })
		st.Series = st.Series[:maxStateEntries]
	}
	if len(st.Cooldowns) > maxStateEntries {
		sort.Slice(st.Cooldowns, func(i, j int) bool { return st.Cooldowns[i].AlertaNs > st.Cooldowns[j].AlertaNs })
		st.Cooldowns = st.Cooldowns[:maxStateEntries]
	}
	return st
}

// importedSeries e uma serie lida do arquivo; os contatos so sao decodificados depois de o
// tamanho do texto passar no limite.
type importedSeries struct {
	Chave    string          `json:"chave"`
	VistoNs  int64           `json:"visto_ns"`
	Contatos json.RawMessage `json:"contatos_ns"`
}

// ImportState restaura o estado exportado. O JSON e lido em fluxo, um elemento por vez, e cada
// um e validado antes de entrar em memoria: chave, tamanho dos contatos e ordem. O que for
// invalido e descartado; as series so valem com o mesmo min_interval (que precisa ser o primeiro
// campo, como ExportState o escreve) e o total e aparado para max_keys (ficam as mais recentes).
// Devolve quantas series e cooldowns ficaram; chave desconhecida ou JSON mal formado e erro.
func (r *Beacon) ImportState(raw []byte) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := expectDelim(dec, '{'); err != nil {
		return 0, fmt.Errorf("estado do beacon ilegivel: %w", err)
	}
	var series []beaconSeries
	var cooldowns []beaconCooldown
	sameMin, sawMin := false, false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return 0, fmt.Errorf("estado do beacon ilegivel: %w", err)
		}
		name, isName := tok.(string)
		if !isName {
			return 0, errors.New("estado do beacon ilegivel: chave de objeto invalida")
		}
		switch name {
		case "min_interval_ns":
			var ns int64
			if err := dec.Decode(&ns); err != nil {
				return 0, fmt.Errorf("estado do beacon ilegivel: min_interval_ns: %w", err)
			}
			sameMin, sawMin = ns == int64(r.cfg.MinInterval), true
		case "series":
			err = streamArray(dec, func() error {
				var s importedSeries
				if err := dec.Decode(&s); err != nil {
					return err
				}
				if sawMin && sameMin && validBeaconKey(s.Chave) && len(s.Contatos) <= maxContactsJSON {
					var contacts []int64
					if json.Unmarshal(s.Contatos, &contacts) == nil && validContacts(contacts, s.VistoNs) {
						series = append(series, beaconSeries{Chave: s.Chave, VistoNs: s.VistoNs, Contatos: contacts})
					}
				}
				return nil
			})
		case "cooldowns":
			err = streamArray(dec, func() error {
				var c beaconCooldown
				if err := dec.Decode(&c); err != nil {
					return err
				}
				if validBeaconKey(c.Chave) && c.AlertaNs > 0 {
					cooldowns = append(cooldowns, c)
				}
				return nil
			})
		default:
			err = fmt.Errorf("chave desconhecida %q", name)
		}
		if err != nil {
			return 0, fmt.Errorf("estado do beacon ilegivel: %w", err)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return 0, fmt.Errorf("estado do beacon ilegivel: %w", err)
	}
	return r.installSeries(series) + r.installCooldowns(cooldowns), nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("esperava %q, veio %v", want, tok)
	}
	return nil
}

// streamArray percorre um array JSON chamando elem para cada elemento (o decoder esta no inicio
// dele). null conta como lista vazia; passar de maxImportElements e erro.
func streamArray(dec *json.Decoder, elem func() error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("esperava uma lista, veio %v", tok)
	}
	for n := 0; dec.More(); n++ {
		if n >= maxImportElements {
			return fmt.Errorf("lista grande demais (mais de %d elementos)", maxImportElements)
		}
		if err := elem(); err != nil {
			return err
		}
	}
	_, err = dec.Token() // ']'
	return err
}

func (r *Beacon) installSeries(valid []beaconSeries) int {
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

func (r *Beacon) installCooldowns(valid []beaconCooldown) int {
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
