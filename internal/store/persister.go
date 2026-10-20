package store

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// PersisterConfig parametriza a gravacao assincrona dos alertas.
type PersisterConfig struct {
	Retention  time.Duration // 0 = nao remove por idade
	MaxAlerts  int           // 0 = sem teto
	BatchSize  int           // padrao 64
	FlushEvery time.Duration // padrao 500 ms
	PruneEvery time.Duration // padrao 1 h
	Logger     *slog.Logger
}

// Persister assina o Bus e grava os alertas em lote, fora do caminho quente do motor:
// se o disco atrasar, o Bus descarta para esta assinatura (contado) em vez de bloquear.
type Persister struct {
	st  *Store
	bus *alerts.Bus
	cfg PersisterConfig
	log *slog.Logger

	dropped atomic.Uint64
}

// NewPersister cria o gravador (inicie com Run).
func NewPersister(st *Store, bus *alerts.Bus, cfg PersisterConfig) *Persister {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 64
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 500 * time.Millisecond
	}
	if cfg.PruneEvery <= 0 {
		cfg.PruneEvery = time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Persister{st: st, bus: bus, cfg: cfg, log: cfg.Logger}
}

// Dropped devolve quantos alertas nao foram gravados por a fila da assinatura estar cheia.
func (p *Persister) Dropped() uint64 { return p.dropped.Load() }

// Run grava ate ctx ser cancelado; ao cancelar, faz uma ultima gravacao do que restou.
func (p *Persister) Run(ctx context.Context) {
	sub := p.bus.Subscribe(1024)
	defer sub.Close()

	flushTick := time.NewTicker(p.cfg.FlushEvery)
	defer flushTick.Stop()
	pruneTick := time.NewTicker(p.cfg.PruneEvery)
	defer pruneTick.Stop()

	batch := make([]*psychoscopev1.Alerta, 0, p.cfg.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Contexto proprio: a gravacao final nao pode ser cancelada pelo encerramento.
		wctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.st.Insert(wctx, batch); err != nil {
			p.log.Error("falha ao gravar alertas", "n", len(batch), "err", err)
		}
		batch = batch[:0]
	}
	prune := func() {
		wctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var cutoff time.Time
		if p.cfg.Retention > 0 {
			cutoff = time.Now().Add(-p.cfg.Retention)
		}
		if n, err := p.st.Prune(wctx, cutoff, p.cfg.MaxAlerts); err != nil {
			p.log.Error("falha ao podar alertas", "err", err)
		} else if n > 0 {
			p.log.Info("alertas antigos removidos", "n", n)
		}
	}

	prune()
	for {
		select {
		case a, ok := <-sub.C:
			if !ok {
				flush()
				return
			}
			batch = append(batch, a)
			if len(batch) >= p.cfg.BatchSize {
				flush()
			}
		case <-flushTick.C:
			p.dropped.Store(sub.Dropped())
			flush()
		case <-pruneTick.C:
			prune()
		case <-ctx.Done():
			for { // esvazia o que ja estava na fila
				select {
				case a, ok := <-sub.C:
					if !ok {
						flush()
						return
					}
					batch = append(batch, a)
				default:
					p.dropped.Store(sub.Dropped())
					flush()
					return
				}
			}
		}
	}
}
