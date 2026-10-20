package rules

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

const maxSeriesLen = 32

type series struct {
	times []time.Time // contatos aceitos, em ordem; no maximo maxSeriesLen
	seen  time.Time   // ultimo evento visto (para despejo)
}

// Beacon detecta beaconing (C2): um cliente que contata o mesmo destino em intervalos
// regulares — conexoes TCP novas (SYN puro) ao mesmo destino:porta, ou consultas DNS ao
// mesmo dominio — com baixa variacao entre os intervalos (MEDIA).
//
// Beacons de minutos nao cabem na janela deslizante (60 s), entao a regra guarda uma
// serie curta de instantes por chave (cliente, alvo), limitada por max_keys. Contatos mais
// proximos que min_interval contam como um so (retransmissoes e rajadas); um silencio
// maior que 3x o intervalo medio reinicia a serie. Falsos positivos esperados: tarefas
// periodicas legitimas (verificacoes de conectividade, polling) — use ignore_domains e
// ignore_ports.
//
// Estado so e acessado pela goroutine do motor; nao ha travas.
type Beacon struct {
	cfg        BeaconConfig
	series     map[string]*series
	cooldown   map[string]time.Time // chave -> fim da supressao (tempo dos eventos)
	ignoreDom  []string
	ignorePort map[uint32]bool
}

func NewBeacon(cfg BeaconConfig) *Beacon {
	b := &Beacon{cfg: cfg, series: map[string]*series{}, cooldown: map[string]time.Time{}, ignorePort: map[uint32]bool{}}
	for _, d := range cfg.IgnoreDomains {
		b.ignoreDom = append(b.ignoreDom, strings.ToLower(strings.TrimSuffix(d, ".")))
	}
	for _, p := range cfg.IgnorePorts {
		b.ignorePort[uint32(p)] = true
	}
	return b
}

func (r *Beacon) Name() string { return NameBeacon }

// classify devolve a chave da serie, o tipo ("tcp"/"dns") e o alvo legivel.
func (r *Beacon) classify(ev *detection.Event) (key, kind, target string, ok bool) {
	src := ev.Net.IpOrigem
	if src == "" {
		return
	}
	switch {
	case ev.IsPureSYN():
		if r.ignorePort[ev.Net.PortaDestino] {
			return
		}
		target = ev.Net.IpDestino + ":" + strconv.Itoa(int(ev.Net.PortaDestino))
		return "tcp|" + src + "|" + target, "tcp", target, true
	case isDNSQuery(ev):
		d := strings.ToLower(strings.TrimSuffix(ev.DNS().DominioConsultado, "."))
		if d == "" || slices.ContainsFunc(r.ignoreDom, func(s string) bool { return d == s || strings.HasSuffix(d, "."+s) }) {
			return
		}
		return "dns|" + src + "|" + d, "dns", d, true
	}
	return
}

func (r *Beacon) Eval(ev *detection.Event, _ *detection.Window) *psychoscopev1.Alerta {
	key, kind, target, ok := r.classify(ev)
	if !ok {
		return nil
	}
	s := r.series[key]
	if s == nil {
		if len(r.series) >= r.cfg.MaxKeys {
			r.evict()
		}
		s = &series{}
		r.series[key] = s
	}
	prevSeen := s.seen
	if ev.At.Before(prevSeen) { // evento fora de ordem
		return nil
	}
	s.seen = ev.At
	if !prevSeen.IsZero() && ev.At.Sub(prevSeen) < r.cfg.MinInterval {
		return nil // rajada ou retransmissao: faz parte do mesmo contato
	}

	if n := len(s.times); n > 0 {
		gap := ev.At.Sub(s.times[n-1])
		reset := r.cfg.MaxInterval
		if n >= 3 {
			reset = time.Duration(3 * float64(s.times[n-1].Sub(s.times[0])) / float64(n-1))
		}
		if gap > reset {
			s.times = s.times[:0]
		}
	}
	s.times = append(s.times, ev.At)
	if len(s.times) > maxSeriesLen {
		s.times = append(s.times[:0], s.times[len(s.times)-maxSeriesLen:]...)
	}
	if len(s.times) < r.cfg.MinSamples {
		return nil
	}

	mean, cv := intervalStats(s.times)
	if mean < r.cfg.MinInterval || mean > r.cfg.MaxInterval || cv > r.cfg.MaxCV {
		return nil
	}
	if until, ok := r.cooldown[key]; ok && ev.At.Before(until) {
		return nil
	}
	if len(r.cooldown) >= r.cfg.MaxKeys {
		for k, until := range r.cooldown {
			if !ev.At.Before(until) {
				delete(r.cooldown, k)
			}
		}
	}
	r.cooldown[key] = ev.At.Add(r.cfg.Cooldown)

	src := ev.Net.IpOrigem
	desc := fmt.Sprintf("Possivel beaconing: %s contata %s a cada ~%s (%d contatos, variacao %.0f%%)",
		src, target, mean.Round(time.Second), len(s.times), cv*100)
	return detection.NewAlert(NameBeacon, psychoscopev1.Severidade_SEVERIDADE_MEDIA, desc, ev, map[string]string{
		"tipo": kind, "origem": src, "alvo": target, "chave": key,
		"intervalo_medio": mean.Round(time.Millisecond).String(), "amostras": strconv.Itoa(len(s.times)),
		"variacao_pct": strconv.FormatFloat(cv*100, 'f', 1, 64),
	})
}

// intervalStats devolve a media dos intervalos entre contatos consecutivos e o coeficiente
// de variacao (desvio padrao / media). Requer pelo menos 2 instantes.
func intervalStats(ts []time.Time) (mean time.Duration, cv float64) {
	n := len(ts) - 1
	if n < 1 {
		return 0, math.Inf(1)
	}
	var sum float64
	iv := make([]float64, n)
	for i := 0; i < n; i++ {
		iv[i] = ts[i+1].Sub(ts[i]).Seconds()
		sum += iv[i]
	}
	m := sum / float64(n)
	if m <= 0 {
		return 0, math.Inf(1)
	}
	var sq float64
	for _, x := range iv {
		sq += (x - m) * (x - m)
	}
	return time.Duration(m * float64(time.Second)), math.Sqrt(sq/float64(n)) / m
}

// evict libera espaco: remove series inativas por mais de 2x max_interval; se ainda
// estiver cheio, as 10% menos recentes.
func (r *Beacon) evict() {
	var newest time.Time
	for _, s := range r.series {
		if s.seen.After(newest) {
			newest = s.seen
		}
	}
	stale := newest.Add(-2 * r.cfg.MaxInterval)
	for k, s := range r.series {
		if s.seen.Before(stale) {
			delete(r.series, k)
		}
	}
	if len(r.series) < r.cfg.MaxKeys {
		return
	}
	type kv struct {
		k    string
		seen time.Time
	}
	all := make([]kv, 0, len(r.series))
	for k, s := range r.series {
		all = append(all, kv{k, s.seen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	for _, e := range all[:max(1, len(all)/10)] {
		delete(r.series, e.k)
	}
}
