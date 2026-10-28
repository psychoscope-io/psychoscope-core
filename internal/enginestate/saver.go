package enginestate

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
)

// snapshotTimeout limita a espera por uma copia do motor (ele atende entre dois eventos).
const snapshotTimeout = 5 * time.Second

// Source e quem fornece o snapshot (satisfeito por *detection.Engine).
type Source interface {
	Snapshot(ctx context.Context) (*detection.Snapshot, error)
	Stats() detection.Stats
}

// Saver grava o snapshot a cada Interval enquanto Run roda, mas so se o motor processou eventos
// desde a ultima vez (o estado so muda com eventos): um Core ocioso nao reescreve nem sincroniza
// o arquivo a cada minuto. A copia e feita na goroutine do motor; a codificacao e a escrita
// acontecem aqui, fora dela.
type Saver struct {
	Store    Store
	Source   Source
	Interval time.Duration
	Log      *slog.Logger

	saves, errs atomic.Uint64
	lastSaved   uint64 // eventos processados na ultima gravacao (so a goroutine de Run toca)
}

// Run grava periodicamente ate ctx ser cancelado. Interval <= 0 nao grava periodicamente
// (so Save, no encerramento); Run retorna na hora.
func (s *Saver) Run(ctx context.Context) {
	if s.Interval <= 0 {
		return
	}
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.snapshotAndSave(ctx)
		}
	}
}

func (s *Saver) snapshotAndSave(ctx context.Context) {
	processed := s.Source.Stats().Processed
	if processed == s.lastSaved {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	snap, err := s.Source.Snapshot(rctx)
	if err != nil {
		if ctx.Err() == nil { // cancelado = encerrando, nao e erro
			s.fail("nao foi possivel copiar o estado do motor", err)
		}
		return
	}
	s.Save(snap)
	s.lastSaved = processed // medido antes da copia: evento que chegou no meio faz a proxima rodada gravar de novo
}

// Save grava um snapshot (o final, tirado com o motor parado, ou o periodico) e conta o resultado.
func (s *Saver) Save(snap *detection.Snapshot) {
	if err := s.Store.Save(snap); err != nil {
		s.fail("nao foi possivel gravar o estado do motor", err)
		return
	}
	s.saves.Add(1)
}

func (s *Saver) fail(msg string, err error) {
	s.errs.Add(1)
	s.Log.Warn(msg, "arquivo", s.Store.Path, "err", err.Error())
}

// Stats devolve quantas gravacoes deram certo e quantas falharam.
func (s *Saver) Stats() (saves, errors uint64) { return s.saves.Load(), s.errs.Load() }
