package app

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// telemetrySink encaminha a telemetria dos modulos ao motor de deteccao. Roda na
// goroutine de leitura da sessao, portanto so enfileira (Submit nunca bloqueia).
type telemetrySink struct {
	ipc.NopHandler
	engine *detection.Engine
	events atomic.Uint64
	log    *slog.Logger
}

func (t *telemetrySink) OnTelemetry(s *ipc.Session, ev *psychoscopev1.EventoTelemetria) {
	if n := t.events.Add(1); n%1000 == 1 {
		t.log.Debug("telemetria recebida", "modulo", s.ID, "total", n)
	}
	switch d := ev.GetDado().(type) {
	case *psychoscopev1.EventoTelemetria_Rede:
		t.engine.Submit(s.ID, d.Rede)
	case *psychoscopev1.EventoTelemetria_Generico:
		if err := t.engine.SubmitGeneric(s.ID, d.Generico); errors.Is(err, detection.ErrInvalidGeneric) {
			t.log.Debug("evento generico rejeitado", "modulo", s.ID, "erro", err)
		}
	}
}
