package detection

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// startEngine roda o motor ate stop() (que espera Run terminar).
func startEngine(t *testing.T, rules []Rule) (*Engine, *recPub, func()) {
	t.Helper()
	pub := &recPub{}
	e := NewEngine(EngineConfig{Window: time.Minute, QueueSize: 1024}, rules, pub)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	return e, pub, func() { cancel(); <-done }
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout esperando: %s", what)
}

func reconf(t *testing.T, e *Engine, rules []Rule, span time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := e.Reconfigure(ctx, rules, span); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}
}

// countRule alerta (com cooldown longo) informando quantos eventos da origem a janela retem.
func countRule(name string) Rule {
	return gatedRule{fnRule{name, func(ev *Event, w *Window) *psychoscopev1.Alerta {
		return NewAlert(name, psychoscopev1.Severidade_SEVERIDADE_ALTA, "x", ev,
			map[string]string{"n": fmt.Sprint(len(w.FromSrc(ev.Net.IpOrigem)))})
	}}, time.Hour}
}

func TestReconfigureSwapsRulesKeepsWindowAndResetsCooldown(t *testing.T) {
	// as duas instancias tem o MESMO nome: e o caso real (mesma regra, limiares novos), e o
	// cooldown e indexado por (regra, chave); se ele nao fosse zerado, o 3o evento seria suprimido
	e, pub, stop := startEngine(t, []Rule{countRule("r")})
	defer stop()

	submit(e, 0, "a") // dispara (n=1) e abre o cooldown de 1h
	submit(e, 1, "a") // suprimido pelo cooldown, mas fica na fila e na janela
	reconf(t, e, []Rule{countRule("r")}, time.Minute)
	// os eventos ja enfileirados foram avaliados antes da troca, com a regra antiga
	if got := e.Stats().Processed; got != 2 {
		t.Fatalf("a fila deve ser esvaziada com as regras antigas antes da troca: processados=%d", got)
	}

	submit(e, 2, "a") // regra nova, cooldown zerado: dispara de novo; a janela manteve os 2 eventos
	eventually(t, "segundo alerta apos a troca", func() bool { return len(pub.list()) == 2 })
	as := pub.list()
	if as[0].Contexto["n"] != "1" {
		t.Fatalf("primeiro alerta: %v", as[0])
	}
	if as[1].Contexto["n"] != "3" {
		t.Fatalf("a regra nova deve enxergar a janela mantida (n=3): %v", as[1])
	}
}

func TestReconfigureAppliesTheNewWindowSpan(t *testing.T) {
	e, _, stop := startEngine(t, nil)
	defer stop()
	for i := 0; i <= 50; i++ {
		submit(e, float64(i), "a")
	}
	eventually(t, "51 eventos processados", func() bool { return e.Stats().Processed == 51 })
	if e.Stats().Window != 51 {
		t.Fatalf("janela de 1 min retem tudo: %d", e.Stats().Window)
	}
	reconf(t, e, nil, 10*time.Second) // so o que tem ate 10 s antes do ultimo evento (t=50)
	if got := e.Stats().Window; got != 11 {
		t.Fatalf("janela de 10 s deve reter os eventos de t=40 a t=50: %d", got)
	}
	reconf(t, e, nil, time.Minute) // aumentar nao ressuscita o que ja saiu
	if got := e.Stats().Window; got != 11 {
		t.Fatalf("o que saiu da janela nao volta: %d", got)
	}
}

func TestReconfigureWithoutRunningEngineTimesOut(t *testing.T) {
	e := NewEngine(EngineConfig{}, nil, &recPub{}) // sem Run
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := e.Reconfigure(ctx, nil, time.Minute); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("motor parado: esperado DeadlineExceeded, veio %v", err)
	}
}

// Corrida: troca de regras enquanto chegam eventos e outros goroutines consultam as estatisticas.
func TestReconfigureUnderLoadIsRaceFree(t *testing.T) {
	e, _, stop := startEngine(t, []Rule{countRule("r0")})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				submit(e, float64(i)*0.01, fmt.Sprintf("src%d", g))
				_ = e.Stats()
			}
		}(g)
	}
	for i := 0; i < 30; i++ {
		reconf(t, e, []Rule{countRule(fmt.Sprintf("r%d", i+1))}, time.Duration(30+i)*time.Second)
	}
	wg.Wait()
	stop() // Run esvazia a fila antes de retornar
	if s := e.Stats(); s.Processed != s.Received || s.Received+s.Dropped != 4*300 {
		t.Fatalf("todo evento aceito deve ser processado: %+v", s)
	}
}
