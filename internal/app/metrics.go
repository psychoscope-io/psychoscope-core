package app

import (
	"context"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	"github.com/psychoscope-io/psychoscope-core/internal/metrics"
	"github.com/psychoscope-io/psychoscope-core/internal/store"
	"github.com/psychoscope-io/psychoscope-core/internal/supervisor"
	"github.com/psychoscope-io/psychoscope-core/internal/version"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// collect monta o instantaneo de metricas do Core. st e persister podem ser nulos.
func collect(started time.Time, engine *detection.Engine, st *store.Store, persister *store.Persister, sup *supervisor.Supervisor) []*psychoscopev1.Metrica {
	ms := append(coreMetrics(started), engineMetrics(engine.Stats())...)
	if st != nil {
		ms = append(ms, storeMetrics(st, persister)...)
	}
	for _, in := range sup.List() {
		ms = append(ms, moduleMetrics(in)...)
	}
	return ms
}

func coreMetrics(started time.Time) []*psychoscopev1.Metrica {
	return []*psychoscopev1.Metrica{
		metrics.Gauge("psychoscope_info", "Informacoes de build do Core (valor sempre 1).", 1, "version", version.Version),
		metrics.Gauge("psychoscope_uptime_seconds", "Tempo desde a partida do Core.", time.Since(started).Seconds()),
	}
}

func engineMetrics(es detection.Stats) []*psychoscopev1.Metrica {
	return []*psychoscopev1.Metrica{
		metrics.Counter("psychoscope_engine_events_received_total", "Eventos aceitos na fila do motor de deteccao.", float64(es.Received)),
		metrics.Counter("psychoscope_engine_events_dropped_total", "Eventos descartados por fila cheia.", float64(es.Dropped)),
		metrics.Counter("psychoscope_engine_events_processed_total", "Eventos processados pelo motor.", float64(es.Processed)),
		metrics.Counter("psychoscope_engine_alerts_total", "Alertas gerados.", float64(es.Alerts)),
		metrics.Counter("psychoscope_engine_alerts_suppressed_total", "Alertas evitados pelo cooldown.", float64(es.Suppressed)),
		metrics.Counter("psychoscope_engine_rule_errors_total", "Falhas de regras contidas (panics).", float64(es.RuleErrors)),
		metrics.Gauge("psychoscope_engine_window_events", "Eventos retidos na janela deslizante.", float64(es.Window)),
	}
}

func storeMetrics(st *store.Store, persister *store.Persister) []*psychoscopev1.Metrica {
	ss := st.Stats()
	ms := []*psychoscopev1.Metrica{
		metrics.Counter("psychoscope_store_alerts_written_total", "Alertas gravados no banco.", float64(ss.Written)),
		metrics.Counter("psychoscope_store_write_errors_total", "Falhas de gravacao no banco.", float64(ss.WriteErrors)),
		metrics.Counter("psychoscope_store_alerts_pruned_total", "Alertas removidos por retencao.", float64(ss.Pruned)),
	}
	if persister != nil {
		ms = append(ms, metrics.Counter("psychoscope_store_alerts_dropped_total", "Alertas nao gravados por fila cheia.", float64(persister.Dropped())))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if n, err := st.Count(ctx); err == nil {
		ms = append(ms, metrics.Gauge("psychoscope_store_alerts", "Alertas armazenados.", float64(n)))
	}
	return ms
}

func moduleMetrics(in supervisor.Info) []*psychoscopev1.Metrica {
	l := []string{"module", in.ID}
	up := 0.0
	if in.State == psychoscopev1.EstadoModulo_ESTADO_CONECTADO || in.State == psychoscopev1.EstadoModulo_ESTADO_PAUSADO {
		up = 1
	}
	ms := []*psychoscopev1.Metrica{
		metrics.Gauge("psychoscope_module_up", "Modulo com sessao IPC ativa (1) ou nao (0).", up, l...),
		metrics.Counter("psychoscope_module_restarts_total", "Reinicios do modulo pelo supervisor.", float64(in.Restarts), l...),
	}
	if !in.LastContact.IsZero() {
		ms = append(ms, metrics.Gauge("psychoscope_module_last_contact_timestamp_seconds", "Ultimo contato com o modulo (epoch).", float64(in.LastContact.Unix()), l...))
	}
	if s := in.LastStatus; s != nil {
		ms = append(ms,
			metrics.Counter("psychoscope_module_events_processed_total", "Eventos enviados pelo modulo (zera ao reiniciar o modulo).", float64(s.EventosProcessados), l...),
			metrics.Counter("psychoscope_module_bytes_processed_total", "Bytes processados pelo modulo.", float64(s.BytesProcessados), l...),
			metrics.Counter("psychoscope_module_packets_captured_total", "Pacotes capturados pelo modulo.", float64(s.PacotesCapturados), l...),
			metrics.Counter("psychoscope_module_packets_dropped_total", "Pacotes descartados pelo modulo.", float64(s.PacotesDescartados), l...),
			metrics.Gauge("psychoscope_module_memory_megabytes", "Memoria residente do modulo.", s.UsoMemoriaMb, l...),
			metrics.Gauge("psychoscope_module_cpu_percent", "Uso de CPU do modulo (% de um nucleo).", s.UsoCpuPercent, l...),
		)
	}
	return ms
}
