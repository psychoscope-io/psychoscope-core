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
type GenericBurst struct {
	cfg   GenericBurstConfig
	types map[string]struct{}
}

func NewGenericBurst(cfg GenericBurstConfig) *GenericBurst {
	types := make(map[string]struct{}, len(cfg.Types))
	for _, t := range cfg.Types {
		types[t] = struct{}{}
	}
	return &GenericBurst{cfg: cfg, types: types}
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

// Key separa o cooldown por modulo, tipo e grupo; so os tipos vigiados e os grupos nao ignorados
// chegam a Eval.
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
	return ev.Module + "|" + ev.Generic.GetTipo() + "|" + strings.Join(vals, "|"), true
}

func (r *GenericBurst) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	tipo := ev.Generic.GetTipo()
	evs := w.OfType(tipo)
	if len(evs) < r.cfg.MinEvents {
		return nil
	}
	vals := r.groupValues(ev)
	cutoff := ev.At.Add(-r.cfg.Window)
	n := 0
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		if e.At.Before(cutoff) {
			break
		}
		if e.Module == ev.Module && slices.Equal(r.groupValues(e), vals) {
			n++
		}
	}
	if n < r.cfg.MinEvents {
		return nil
	}
	ctx := map[string]string{
		"modulo": ev.Module, "evento_tipo": tipo, "ocorrencias": fmt.Sprint(n), "janela": r.cfg.Window.String(),
	}
	desc := fmt.Sprintf("Rajada de eventos %q do módulo %s: %d em %s", tipo, ev.Module, n, r.cfg.Window)
	if len(r.cfg.GroupBy) > 0 {
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
