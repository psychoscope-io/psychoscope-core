package rules

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// GenericBurst detecta uma rajada de eventos genericos do mesmo tipo vindos do mesmo modulo (MEDIA).
// E a regra de uso geral para modulos sem regra propria: o operador escolhe os tipos a vigiar
// (Types; vazio = regra inativa) e, se quiser, os atributos que separam os grupos (GroupBy).
//
// Conta por grupo com estado proprio (uma serie de instantes por chave), e nao varrendo a janela do
// motor: a varredura custaria O(eventos do tipo) por evento, e um modulo que enviasse muitos eventos
// travaria o motor para todas as regras. O estado e limitado por MaxKeys e so o toca a goroutine do
// motor. Nao sobrevive a reinicio nem a Reconfigure (o beacon, que precisa disso, e a excecao).
type GenericBurst struct {
	cfg    GenericBurstConfig
	types  map[string]struct{}
	series map[string]*burstSeries
}

// burstSeries guarda os instantes (no tempo dos eventos) ainda dentro da janela de um grupo.
type burstSeries struct {
	times []time.Time
	head  int
}

func (s *burstSeries) len() int { return len(s.times) - s.head }

// add registra o instante e descarta os que ficaram antes de cutoff.
func (s *burstSeries) add(at, cutoff time.Time) {
	s.times = append(s.times, at)
	for s.head < len(s.times) && s.times[s.head].Before(cutoff) {
		s.head++
	}
	if s.head > 64 && s.head*2 > len(s.times) {
		s.times = append([]time.Time(nil), s.times[s.head:]...)
		s.head = 0
	}
}

func (s *burstSeries) last() time.Time {
	if s.len() == 0 {
		return time.Time{}
	}
	return s.times[len(s.times)-1]
}

func NewGenericBurst(cfg GenericBurstConfig) *GenericBurst {
	types := make(map[string]struct{}, len(cfg.Types))
	for _, t := range cfg.Types {
		types[t] = struct{}{}
	}
	return &GenericBurst{cfg: cfg, types: types, series: map[string]*burstSeries{}}
}

func (r *GenericBurst) Name() string            { return NameGenericBurst }
func (r *GenericBurst) Kind() detection.Kind    { return detection.KindGeneric }
func (r *GenericBurst) Cooldown() time.Duration { return r.cfg.Cooldown }

// groupValues devolve os valores dos atributos de GroupBy no evento ("" para o que falta).
func (r *GenericBurst) groupValues(ev *detection.Event) []string {
	vals := make([]string, len(r.cfg.GroupBy))
	for i, attr := range r.cfg.GroupBy {
		vals[i] = ev.Generic.GetAtributos()[attr]
	}
	return vals
}

// Key separa o cooldown e a serie por modulo, tipo e grupo; so os tipos vigiados e os grupos nao
// ignorados chegam a Eval. O separador e um caractere de controle, que o motor rejeita nos valores
// (detection.NewGenericEvent), entao duas chaves diferentes nunca colidem.
func (r *GenericBurst) Key(ev *detection.Event) (string, bool) {
	if _, watched := r.types[ev.Generic.GetTipo()]; !watched {
		return "", false
	}
	vals := r.groupValues(ev)
	for _, v := range vals {
		if slices.Contains(r.cfg.IgnoreGroups, v) {
			return "", false
		}
	}
	return ev.Module + "\x1f" + ev.Generic.GetTipo() + "\x1f" + strings.Join(vals, "\x1f"), true
}

func (r *GenericBurst) Eval(ev *detection.Event, _ *detection.Window) *psychoscopev1.Alerta {
	key, ok := r.Key(ev)
	if !ok {
		return nil
	}
	s := r.series[key]
	if s == nil {
		r.makeRoom(ev.At)
		s = &burstSeries{}
		r.series[key] = s
	}
	s.add(ev.At, ev.At.Add(-r.cfg.Window))
	n := s.len()
	if n < r.cfg.MinEvents {
		return nil
	}
	delete(r.series, key) // a proxima rajada recomeca a contagem
	return r.alert(ev, n)
}

// makeRoom abre espaco para uma serie nova quando o teto de grupos foi atingido: descarta as que ja
// sairam da janela e, se ainda for preciso, as 10% menos recentes.
func (r *GenericBurst) makeRoom(now time.Time) {
	if len(r.series) < r.cfg.MaxKeys {
		return
	}
	cutoff := now.Add(-r.cfg.Window)
	for k, s := range r.series {
		if s.last().Before(cutoff) {
			delete(r.series, k)
		}
	}
	if len(r.series) < r.cfg.MaxKeys {
		return
	}
	keys := make([]string, 0, len(r.series))
	for k := range r.series {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return r.series[a].last().Compare(r.series[b].last()) })
	for _, k := range keys[:max(len(keys)/10, 1)] {
		delete(r.series, k)
	}
}

func (r *GenericBurst) alert(ev *detection.Event, n int) *psychoscopev1.Alerta {
	tipo := ev.Generic.GetTipo()
	ctx := map[string]string{
		"modulo": ev.Module, "evento_tipo": tipo, "ocorrencias": fmt.Sprint(n), "janela": r.cfg.Window.String(),
	}
	desc := fmt.Sprintf("Rajada de eventos %q do módulo %s: %d em %s", tipo, ev.Module, n, r.cfg.Window)
	if vals := r.groupValues(ev); len(vals) > 0 {
		parts := make([]string, len(vals))
		for i, attr := range r.cfg.GroupBy {
			parts[i] = attr + "=" + vals[i]
		}
		ctx["grupo"] = strings.Join(parts, ", ")
		desc += " (" + ctx["grupo"] + ")"
		if len(vals) == 1 {
			ctx["grupo_valor"] = vals[0] // o que ignore_groups aceita, para a excecao sugerida
		}
	}
	return detection.NewAlert(NameGenericBurst, psychoscopev1.Severidade_SEVERIDADE_MEDIA, desc, ev, ctx)
}
