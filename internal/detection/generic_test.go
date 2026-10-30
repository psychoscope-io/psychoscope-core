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

func TestNewGenericEventRejectsTimestampTooFarAhead(t *testing.T) {
	cases := []struct {
		name string
		ts   time.Duration // em relacao a chegada
		ok   bool
	}{
		{"no passado", -time.Hour, true},
		{"na chegada", 0, true},
		{"dentro da tolerancia", 4 * time.Minute, true},
		{"na tolerancia", maxGenericSkew, true},
		{"alem da tolerancia", maxGenericSkew + time.Second, false},
		{"anos a frente", 24 * 365 * 50 * time.Hour, false},
	}
	for _, c := range cases {
		g := generic("t", nil)
		g.Timestamp = tsOf(t0.Add(c.ts))
		ev, err := NewGenericEvent("m", g, t0)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: erro inesperado: %v", c.name, err)
		case c.ok && !ev.At.Equal(t0.Add(c.ts)):
			t.Errorf("%s: At=%v", c.name, ev.At)
		case !c.ok && !errors.Is(err, ErrInvalidGeneric):
			t.Errorf("%s: esperava ErrInvalidGeneric, veio %v", c.name, err)
		}
	}
}

func TestFutureGenericTimestampCannotFlushTheWindow(t *testing.T) {
	_, pub := runEngine(t, []Rule{kindRule{"r.rede", KindNet}}, func(e *Engine) {
		submit(e, 0, "1.1.1.1")
		g := generic("t", nil)
		g.Timestamp = tsOf(time.Now().Add(100 * 365 * 24 * time.Hour))
		if err := e.SubmitGeneric("mod-hostil", g); !errors.Is(err, ErrInvalidGeneric) {
			t.Errorf("deveria rejeitar: %v", err)
		}
		submit(e, 1, "1.1.1.2")
	})
	if n := len(pub.list()); n != 2 {
		t.Fatalf("os eventos de rede nao podem ser afetados: %d alertas", n)
	}
}

func TestWindowByteCapBoundsHeavyGenericEvents(t *testing.T) {
	w := NewWindow(time.Hour, 1000) // teto de bytes: 1000 * 256
	big := map[string]string{}
	for i := 0; i < maxGenericAttrs; i++ {
		big["chave"+string(rune('a'+i%26))+string(rune('a'+i/26))] = strings.Repeat("x", maxGenericValueSize)
	}
	for i := 0; i < 500; i++ {
		w.Add(&Event{Module: "m", At: t0.Add(time.Duration(i) * time.Second), Generic: generic("pesado", big)})
	}
	if w.Len() >= 500 || w.bytes > w.maxBytes {
		t.Fatalf("o teto de bytes deveria limitar a janela: len=%d bytes=%d max=%d", w.Len(), w.bytes, w.maxBytes)
	}
	if got := len(w.OfType("pesado")); got != w.Len() {
		t.Fatalf("indice e fila divergem: indice=%d fila=%d", got, w.Len())
	}
	// so eventos de rede continuam limitados pela contagem, como antes
	n := NewWindow(time.Hour, 5)
	for i := 0; i < 20; i++ {
		n.Add(evAt(float64(i), "a", "x"))
	}
	if n.Len() != 5 {
		t.Fatalf("eventos de rede: len=%d, esperado 5", n.Len())
	}
	// o peso volta a zero quando tudo sai
	w.Add(evAt(100000, "z", "z"))
	if w.Len() != 1 || w.bytes != netEventWeight {
		t.Fatalf("contabilidade de bytes: len=%d bytes=%d", w.Len(), w.bytes)
	}
}

func TestEventWithoutVariantHasNoKindAndReachesNoRule(t *testing.T) {
	if (&Event{}).Kind() != 0 {
		t.Fatal("evento sem variante nao tem Kind")
	}
	_, pub := runEngine(t, []Rule{kindRule{"r.rede", KindNet}, kindRule{"r.generica", KindGeneric}}, func(e *Engine) {
		e.Submit("m", nil) // evento de rede ausente
	})
	if n := len(pub.list()); n != 0 {
		t.Fatalf("nenhuma regra deve receber evento sem variante: %d alertas", n)
	}
}
