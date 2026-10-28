package app

import (
	"github.com/psychoscope-io/psychoscope-core/internal/enginestate"
	"github.com/psychoscope-io/psychoscope-core/internal/metrics"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// openEngineState restaura o estado salvo do motor (antes de Run) e prepara o gravador. Um
// arquivo ilegivel, velho ou de versao desconhecida e descartado com um aviso, e o Core sobe
// com o motor vazio: o estado e so uma otimizacao. Sem EngineStatePath o recurso fica desligado.
func (d *daemon) openEngineState() {
	if d.cfg.EngineStatePath == "" {
		return
	}
	log := d.log.With("componente", "estado-do-motor")
	store := enginestate.Store{Path: d.cfg.EngineStatePath}
	snap, err := store.Load()
	switch {
	case err != nil:
		log.Warn("estado do motor descartado; o motor comeca vazio", "arquivo", store.Path, "err", err.Error())
	case snap != nil:
		res := d.engine.Restore(snap)
		log.Info("estado do motor restaurado", "cooldowns", res.Cooldowns, "regras", res.Rules)
	}
	d.stateSaver = &enginestate.Saver{Store: store, Source: d.engine, Interval: d.cfg.EngineStateInterval, Log: log}
}

// saveFinalEngineState grava o estado depois que o motor parou (State exige Run encerrado). Sem
// nenhum evento processado nesta execucao nada mudou: o arquivo restaurado fica como esta, com o
// instante em que foi gravado, em vez de ser renovado a cada partida sem trafego.
func (d *daemon) saveFinalEngineState() {
	if d.stateSaver != nil && d.engine.Stats().Processed > 0 {
		d.stateSaver.Save(d.engine.State())
	}
}

func engineStateMetrics(s *enginestate.Saver) []*psychoscopev1.Metrica {
	saves, errs := s.Stats()
	return []*psychoscopev1.Metrica{
		metrics.Counter("psychoscope_engine_state_saves_total", "Gravacoes do estado do motor em disco.", float64(saves)),
		metrics.Counter("psychoscope_engine_state_save_errors_total", "Falhas ao gravar o estado do motor.", float64(errs)),
	}
}
