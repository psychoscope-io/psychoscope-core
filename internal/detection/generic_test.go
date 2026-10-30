package detection

import (
	"errors"
	"strings"
	"testing"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func generic(tipo string, attrs map[string]string) *psychoscopev1.EventoGenerico {
	return &psychoscopev1.EventoGenerico{Tipo: tipo, Atributos: attrs}
}

func TestNewGenericEventChecksContractLimits(t *testing.T) {
	many := map[string]string{}
	for i := 0; i < 33; i++ {
		many["k"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	cases := []struct {
		name string
		g    *psychoscopev1.EventoGenerico
		want string // vazio = valido; senao, trecho do motivo
	}{
		{"valido", generic("login.falha", map[string]string{"usuario": "ana", "origem-ip": "192.0.2.1"}), ""},
		{"sem atributos", generic("heartbeat", nil), ""},
		{"tipo vazio", generic("", nil), "tipo"},
		{"tipo com maiuscula", generic("Login", nil), "tipo"},
		{"tipo com espaco", generic("login falha", nil), "tipo"},
		{"tipo com 65 caracteres", generic(strings.Repeat("a", 65), nil), "tipo"},
		{"tipo com 64 caracteres", generic(strings.Repeat("a", 64), nil), ""},
		{"chave invalida", generic("t", map[string]string{"Chave": "v"}), "chave"},
		{"chave vazia", generic("t", map[string]string{"": "v"}), "chave"},
		{"atributos demais", generic("t", many), "atributos"},
		{"valor com 257 bytes", generic("t", map[string]string{"k": strings.Repeat("x", 257)}), "valor"},
		{"valor com 256 bytes", generic("t", map[string]string{"k": strings.Repeat("x", 256)}), ""},
	}
	for _, c := range cases {
		ev, err := NewGenericEvent("mod-x", c.g, t0)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: erro inesperado: %v", c.name, err)
		case c.want == "" && (ev.Kind() != KindGeneric || ev.Module != "mod-x" || ev.Net != nil):
			t.Errorf("%s: evento mal montado: %+v", c.name, ev)
		case c.want != "" && !errors.Is(err, ErrInvalidGeneric):
			t.Errorf("%s: esperava ErrInvalidGeneric, veio %v", c.name, err)
		case c.want != "" && !strings.Contains(err.Error(), c.want):
			t.Errorf("%s: o motivo deveria citar %q: %v", c.name, c.want, err)
		}
	}
}

func TestNewGenericEventUsesModuleTimestampOrArrival(t *testing.T) {
	arr := t0.Add(time.Hour)
	if ev, _ := NewGenericEvent("m", generic("t", nil), arr); !ev.At.Equal(arr) {
		t.Errorf("sem timestamp deve usar a chegada: %v", ev.At)
	}
	g := generic("t", nil)
	g.Timestamp = tsOf(t0.Add(5 * time.Minute))
	if ev, _ := NewGenericEvent("m", g, arr); !ev.At.Equal(t0.Add(5 * time.Minute)) {
		t.Errorf("deve usar o timestamp do modulo: %v", ev.At)
	}
}

func TestWindowIndexesGenericEventsByTypeAndEvicts(t *testing.T) {
	w := NewWindow(10*time.Second, 100)
	at := func(sec float64, tipo string) *Event {
		return &Event{Module: "m", At: t0.Add(time.Duration(sec * float64(time.Second))), Generic: generic(tipo, nil)}
	}
	w.Add(at(0, "a"))
	w.Add(at(5, "b"))
	w.Add(at(9, "a"))
	w.Add(evAt(9, "1.1.1.1", "2.2.2.2")) // evento de rede convive com os genericos
	if w.Len() != 4 || len(w.OfType("a")) != 2 || len(w.OfType("b")) != 1 || len(w.FromSrc("1.1.1.1")) != 1 {
		t.Fatalf("indices: len=%d a=%d b=%d", w.Len(), len(w.OfType("a")), len(w.OfType("b")))
	}
	w.Add(at(100, "c")) // tudo anterior sai
	if w.Len() != 1 || w.OfType("a") != nil || w.OfType("b") != nil || len(w.byType) != 1 || len(w.bySrc) != 0 {
		t.Fatalf("apos evicao: len=%d tipos=%d src=%d", w.Len(), len(w.byType), len(w.bySrc))
	}
}

// kindRule dispara um alerta com o seu nome para cada evento que o motor lhe entrega.
type kindRule struct {
	name string
	kind Kind
}

func (k kindRule) Name() string { return k.name }
func (k kindRule) Kind() Kind   { return k.kind }
func (k kindRule) Eval(ev *Event, _ *Window) *psychoscopev1.Alerta {
	return NewAlert(k.name, psychoscopev1.Severidade_SEVERIDADE_BAIXA, "visto", ev, nil)
}

func TestEngineDeliversEachRuleOnlyEventsOfItsKind(t *testing.T) {
	rules := []Rule{kindRule{"r.rede", KindNet}, kindRule{"r.generica", KindGeneric}}
	e, pub := runEngine(t, rules, func(e *Engine) {
		submit(e, 0, "1.1.1.1")
		submit(e, 1, "1.1.1.2")
		if err := e.SubmitGeneric("mod-g", generic("login.falha", nil)); err != nil {
			t.Errorf("SubmitGeneric: %v", err)
		}
	})
	got := map[string]int{}
	for _, a := range pub.list() {
		got[a.Regra]++
	}
	if got["r.rede"] != 2 || got["r.generica"] != 1 {
		t.Fatalf("cada regra deve ver so a sua variante: %v", got)
	}
	if st := e.Stats(); st.Received != 3 || st.Processed != 3 || st.Rejected != 0 {
		t.Fatalf("contadores: %+v", st)
	}
}

func TestSubmitGenericRejectsInvalidWithoutProcessing(t *testing.T) {
	e, pub := runEngine(t, []Rule{kindRule{"r.generica", KindGeneric}}, func(e *Engine) {
		if err := e.SubmitGeneric("mod-g", generic("INVALIDO", nil)); !errors.Is(err, ErrInvalidGeneric) {
			t.Errorf("esperava ErrInvalidGeneric, veio %v", err)
		}
	})
	if st := e.Stats(); st.Rejected != 1 || st.Received != 0 || st.Processed != 0 || len(pub.list()) != 0 {
		t.Fatalf("rejeitado nao entra na fila: %+v alertas=%d", st, len(pub.list()))
	}
}

func TestSubmitGenericReportsFullQueueAndCountsIt(t *testing.T) {
	e := NewEngine(EngineConfig{Window: time.Minute, QueueSize: 1}, nil, &recPub{}) // sem Run: a fila nao esvazia
	if err := e.SubmitGeneric("m", generic("t", nil)); err != nil {
		t.Fatal(err)
	}
	if err := e.SubmitGeneric("m", generic("t", nil)); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("esperava ErrQueueFull, veio %v", err)
	}
	if st := e.Stats(); st.Received != 1 || st.Dropped != 1 {
		t.Fatalf("contadores: %+v", st)
	}
}
