package app

import (
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
	if rede := ev.GetRede(); rede != nil {
		t.engine.Submit(s.ID, rede)
	}
}
