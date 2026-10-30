package app

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

type countingPub struct{ alerts chan *psychoscopev1.Alerta }

func (c countingPub) Publish(a *psychoscopev1.Alerta) { c.alerts <- a }

// genericRule dispara para todo evento generico do tipo "login.falha".
type genericRule struct{}

func (genericRule) Name() string         { return "teste.generica" }
func (genericRule) Kind() detection.Kind { return detection.KindGeneric }
func (genericRule) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	if len(w.OfType("login.falha")) == 0 {
		return nil
	}
	return detection.NewAlert("teste.generica", psychoscopev1.Severidade_SEVERIDADE_BAIXA, "login.falha visto", ev, ev.Generic.GetAtributos())
}

func genericTelemetry(tipo string, attrs map[string]string) *psychoscopev1.EventoTelemetria {
	return &psychoscopev1.EventoTelemetria{IdModulo: "mod-g", Dado: &psychoscopev1.EventoTelemetria_Generico{
		Generico: &psychoscopev1.EventoGenerico{Tipo: tipo, Atributos: attrs}}}
}

func TestTelemetrySinkRoutesGenericEventsToTheEngine(t *testing.T) {
	pub := countingPub{alerts: make(chan *psychoscopev1.Alerta, 4)}
	eng := detection.NewEngine(detection.EngineConfig{Window: time.Minute}, []detection.Rule{genericRule{}}, pub)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { eng.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	sink := &telemetrySink{engine: eng, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	sess := &ipc.Session{ID: "mod-g"}
	sink.OnTelemetry(sess, genericTelemetry("login.falha", map[string]string{"usuario": "ana"}))
	sink.OnTelemetry(sess, genericTelemetry("INVALIDO", nil)) // fora dos limites: rejeitado, sem derrubar nada

	select {
	case a := <-pub.alerts:
		if a.Regra != "teste.generica" || a.IdModuloOrigem != "mod-g" || a.Contexto["usuario"] != "ana" {
			t.Fatalf("alerta: %v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("o evento generico nao chegou a regra")
	}
	if st := eng.Stats(); st.Rejected != 1 {
		t.Fatalf("o evento invalido deveria ser contado como rejeitado: %+v", st)
	}
}
