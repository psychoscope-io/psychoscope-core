package detection

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var t0 = time.Unix(1_700_000_000, 0).UTC()

func evAt(sec float64, src, dst string) *Event {
	return &Event{Module: "m", At: t0.Add(time.Duration(sec * float64(time.Second))),
		Net: &psychoscopev1.EventoFluxoRede{IpOrigem: src, IpDestino: dst}}
}

func TestWindowEvictsByTimeAndKeepsIndexesConsistent(t *testing.T) {
	w := NewWindow(10*time.Second, 1000)
	w.Add(evAt(0, "a", "x"))
	w.Add(evAt(5, "b", "x"))
	w.Add(evAt(9, "a", "y"))
	if w.Len() != 3 || len(w.FromSrc("a")) != 2 || len(w.ToDst("x")) != 2 {
		t.Fatalf("estado inicial: len=%d", w.Len())
	}
	w.Add(evAt(12, "c", "z")) // cutoff = 2s: sai o evento de t=0
	if w.Len() != 3 || len(w.FromSrc("a")) != 1 || len(w.ToDst("x")) != 1 {
		t.Fatalf("apos evicao por tempo: len=%d a=%d x=%d", w.Len(), len(w.FromSrc("a")), len(w.ToDst("x")))
	}
	w.Add(evAt(100, "d", "z")) // tudo anterior sai
	if w.Len() != 1 || w.FromSrc("a") != nil || w.ToDst("x") != nil || len(w.bySrc) != 1 || len(w.byDst) != 1 {
		t.Fatalf("janela deveria ter so o ultimo: len=%d src=%d dst=%d", w.Len(), len(w.bySrc), len(w.byDst))
	}
	if !w.Now().Equal(t0.Add(100 * time.Second)) {
		t.Fatalf("Now=%v", w.Now())
	}
}

func TestWindowCapacityCap(t *testing.T) {
	w := NewWindow(time.Hour, 5)
	for i := 0; i < 20; i++ {
		w.Add(evAt(float64(i), "a", "x"))
	}
	if w.Len() != 5 || len(w.FromSrc("a")) != 5 {
		t.Fatalf("len=%d", w.Len())
	}
	if first := w.FromSrc("a")[0]; !first.At.Equal(t0.Add(15 * time.Second)) {
		t.Fatalf("deveria reter os 5 mais novos, primeiro=%v", first.At)
	}
}

func TestWindowOutOfOrderDoesNotRewindClock(t *testing.T) {
	w := NewWindow(10*time.Second, 100)
	w.Add(evAt(50, "a", "x"))
	w.Add(evAt(1, "a", "x")) // atrasado: ja fora da janela
	if !w.Now().Equal(t0.Add(50 * time.Second)) {
		t.Fatal("relogio nao pode voltar")
	}
	if w.Len() != 1 {
		t.Fatalf("evento atrasado deveria ser descartado, len=%d", w.Len())
	}
}

// Propriedade: contra uma implementacao ingenua, com tempos crescentes e chaves aleatorias.
func TestWindowMatchesBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	span := 20 * time.Second
	w := NewWindow(span, 150)
	var all []*Event
	cur := 0.0
	for i := 0; i < 5000; i++ {
		cur += rng.Float64() * 0.5
		e := evAt(cur, fmt.Sprintf("s%d", rng.Intn(6)), fmt.Sprintf("d%d", rng.Intn(6)))
		w.Add(e)
		all = append(all, e)

		// esperado: no maximo 150 mais recentes, todos dentro do span
		cut := e.At.Add(-span)
		var want []*Event
		for _, x := range all {
			if !x.At.Before(cut) {
				want = append(want, x)
			}
		}
		if len(want) > 150 {
			want = want[len(want)-150:]
		}
		if w.Len() != len(want) {
			t.Fatalf("i=%d len=%d want=%d", i, w.Len(), len(want))
		}
		if i%97 == 0 {
			for s := 0; s < 6; s++ {
				key := fmt.Sprintf("s%d", s)
				var ws []*Event
				for _, x := range want {
					if x.Net.IpOrigem == key {
						ws = append(ws, x)
					}
				}
				got := w.FromSrc(key)
				if len(got) != len(ws) {
					t.Fatalf("i=%d src %s: %d vs %d", i, key, len(got), len(ws))
				}
				for j := range got {
					if got[j] != ws[j] {
						t.Fatalf("ordem divergente em %s", key)
					}
				}
			}
		}
	}
}

func TestNewEventTimestampFallback(t *testing.T) {
	arr := t0.Add(time.Hour)
	if e := NewEvent("m", &psychoscopev1.EventoFluxoRede{}, arr); !e.At.Equal(arr) {
		t.Fatal("sem timestamp deve usar a chegada")
	}
	at := t0.Add(5 * time.Minute)
	n := &psychoscopev1.EventoFluxoRede{TimestampCaptura: tsOf(at)}
	if e := NewEvent("m", n, arr); !e.At.Equal(at) {
		t.Fatalf("deve usar o timestamp de captura: %v", e.At)
	}
}

// ---- engine ----

type recPub struct {
	mu sync.Mutex
	as []*psychoscopev1.Alerta
}

func (r *recPub) Publish(a *psychoscopev1.Alerta) { r.mu.Lock(); r.as = append(r.as, a); r.mu.Unlock() }
func (r *recPub) list() []*psychoscopev1.Alerta {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*psychoscopev1.Alerta(nil), r.as...)
}

type fnRule struct {
	name string
	fn   func(*Event, *Window) *psychoscopev1.Alerta
}

func (f fnRule) Name() string                                   { return f.name }
func (f fnRule) Eval(e *Event, w *Window) *psychoscopev1.Alerta { return f.fn(e, w) }

type gatedRule struct {
	fnRule
	cooldown time.Duration
}

func (g gatedRule) Key(e *Event) (string, bool) { return e.Net.IpOrigem, e.Net.IpOrigem != "" }
func (g gatedRule) Cooldown() time.Duration     { return g.cooldown }

func runEngine(t *testing.T, rules []Rule, feed func(*Engine)) (*Engine, *recPub) {
	t.Helper()
	pub := &recPub{}
	e := NewEngine(EngineConfig{Window: time.Minute, QueueSize: 1024}, rules, pub)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	feed(e)
	cancel()
	<-done // Run esvazia a fila antes de retornar
	return e, pub
}

func fire(name string) func(*Event, *Window) *psychoscopev1.Alerta {
	return func(ev *Event, _ *Window) *psychoscopev1.Alerta {
		return NewAlert(name, psychoscopev1.Severidade_SEVERIDADE_ALTA, "disparou", ev, map[string]string{"k": "v"})
	}
}

func submit(e *Engine, sec float64, src string) {
	e.Submit("mod-a", &psychoscopev1.EventoFluxoRede{IpOrigem: src, IpDestino: "9.9.9.9",
		TimestampCaptura: tsOf(t0.Add(time.Duration(sec * float64(time.Second))))})
}

func TestEnginePublishesAlertWithCommonFields(t *testing.T) {
	_, pub := runEngine(t, []Rule{fnRule{"r.teste", fire("")}}, func(e *Engine) { submit(e, 0, "1.1.1.1") })
	as := pub.list()
	if len(as) != 1 {
		t.Fatalf("alertas: %d", len(as))
	}
	a := as[0]
	if a.Regra != "r.teste" || a.IdAlerta == "" || a.Timestamp == nil || a.IdModuloOrigem != "mod-a" ||
		a.Severidade != psychoscopev1.Severidade_SEVERIDADE_ALTA || a.Contexto["k"] != "v" || a.Contexto["evento_ts"] == "" {
		t.Fatalf("alerta: %v", a)
	}
}

func TestEngineCooldownIsPerKeyAndInEventTime(t *testing.T) {
	r := gatedRule{fnRule{"r.gated", fire("r.gated")}, 30 * time.Second}
	e, pub := runEngine(t, []Rule{r}, func(e *Engine) {
		submit(e, 0, "a")  // dispara
		submit(e, 5, "a")  // suprimido (mesma chave)
		submit(e, 6, "b")  // outra chave: dispara
		submit(e, 29, "a") // ainda suprimido
		submit(e, 31, "a") // cooldown expirou (30s): dispara
	})
	as := pub.list()
	if len(as) != 3 {
		t.Fatalf("esperado 3 alertas, obtido %d", len(as))
	}
	if as[0].Contexto["chave"] != "a" || as[1].Contexto["chave"] != "b" {
		t.Fatalf("chaves: %v %v", as[0].Contexto, as[1].Contexto)
	}
	st := e.Stats()
	if st.Alerts != 3 || st.Suppressed != 2 || st.Processed != 5 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestEngineGatedKeySkipsEvaluation(t *testing.T) {
	var evals int
	r := gatedRule{fnRule{"r", func(*Event, *Window) *psychoscopev1.Alerta { evals++; return nil }}, time.Second}
	runEngine(t, []Rule{r}, func(e *Engine) {
		e.Submit("m", &psychoscopev1.EventoFluxoRede{}) // sem IP de origem: Key retorna ok=false
		submit(e, 0, "a")
	})
	if evals != 1 {
		t.Fatalf("Eval chamado %d vezes, esperado 1", evals)
	}
}

func TestEngineContainsRulePanics(t *testing.T) {
	bad := fnRule{"r.ruim", func(*Event, *Window) *psychoscopev1.Alerta { panic("boom") }}
	good := fnRule{"r.boa", fire("r.boa")}
	e, pub := runEngine(t, []Rule{bad, good}, func(e *Engine) { submit(e, 0, "a"); submit(e, 1, "a") })
	if len(pub.list()) != 2 {
		t.Fatalf("a regra boa deve continuar funcionando: %d alertas", len(pub.list()))
	}
	if e.Stats().RuleErrors != 2 {
		t.Fatalf("RuleErrors=%d", e.Stats().RuleErrors)
	}
}

func TestEngineSubmitNeverBlocksAndCountsDrops(t *testing.T) {
	e := NewEngine(EngineConfig{QueueSize: 2}, nil, &recPub{}) // sem Run: fila enche
	ok := 0
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			if e.Submit("m", &psychoscopev1.EventoFluxoRede{}) {
				ok++
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Submit bloqueou")
	}
	st := e.Stats()
	if ok != 2 || st.Received != 2 || st.Dropped != 8 {
		t.Fatalf("ok=%d stats=%+v", ok, st)
	}
}

func TestRulesSeeEventAlreadyInWindow(t *testing.T) {
	var seen int
	r := fnRule{"r", func(ev *Event, w *Window) *psychoscopev1.Alerta {
		seen = len(w.FromSrc(ev.Net.IpOrigem))
		return nil
	}}
	runEngine(t, []Rule{r}, func(e *Engine) { submit(e, 0, "a"); submit(e, 1, "a"); submit(e, 2, "a") })
	if seen != 3 {
		t.Fatalf("a regra deve ver o proprio evento na janela, viu %d", seen)
	}
}

func tsOf(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }
