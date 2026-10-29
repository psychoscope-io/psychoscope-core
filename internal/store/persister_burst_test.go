package store

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
)

// Uma tempestade publica milhares de alertas em instantes, muito mais rapido do que o SQLite
// grava: a fila da assinatura tem de absorver a rajada inteira, sem perder nenhum alerta.
func TestPersisterAbsorbsAlertBurst(t *testing.T) {
	s := open(t)
	bus := alerts.NewBus()
	p := NewPersister(s, bus, PersisterConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	// o Run assina o barramento ao partir: publica um sentinela ate ele ser gravado
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		bus.Publish(alert("sentinela", "r", 1, "m", t0))
		if c, _ := s.Count(context.Background()); c > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("o gravador nao assinou o barramento")
		}
	}
	const burst = 15_000 // cabe na fila de 16 384 mesmo se o gravador nao rodar durante a rajada
	for i := 0; i < burst; i++ {
		bus.Publish(alert(fmt.Sprintf("b%06d", i), "r", 1, "m", t0.Add(time.Duration(i)*time.Millisecond)))
	}
	cancel() // o encerramento grava o que ficou na fila
	<-done
	if c, _ := s.Count(context.Background()); c != burst+1 {
		t.Fatalf("gravados %d, queria %d", c, burst+1)
	}
	if p.Dropped() != 0 {
		t.Errorf("descartados %d", p.Dropped())
	}
}

func TestPersisterWarnsWhenAlertsAreDropped(t *testing.T) {
	var out bytes.Buffer
	p := NewPersister(open(t), alerts.NewBus(), PersisterConfig{Logger: slog.New(slog.NewTextHandler(&out, nil))})
	p.noteDropped(0)
	if out.Len() != 0 {
		t.Fatalf("avisou sem perda: %s", out.String())
	}
	p.noteDropped(5)
	p.noteDropped(5) // sem perda nova: nao repete o aviso
	p.noteDropped(8)
	if got := strings.Count(out.String(), "alertas descartados"); got != 2 {
		t.Fatalf("avisos = %d, queria 2: %s", got, out.String())
	}
	if p.Dropped() != 8 {
		t.Errorf("Dropped = %d, queria 8", p.Dropped())
	}
}
