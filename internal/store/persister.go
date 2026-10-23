package store

import (
	"context"
	"io"
	"log/slog"
	"sync"
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

	mu        sync.Mutex    // protege retention e maxAlerts (SetLimits roda fora de Run)
	retention time.Duration // 0 = nao remove por idade
	maxAlerts int           // 0 = sem teto
	pruneNow  chan struct{} // pede uma poda imediata (capacidade 1: pedidos se fundem)
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
	return &Persister{st: st, bus: bus, cfg: cfg, log: cfg.Logger,
		retention: cfg.Retention, maxAlerts: cfg.MaxAlerts, pruneNow: make(chan struct{}, 1)}
}

// SetLimits troca a retencao por idade e o teto de alertas (0 desliga cada limite) e pede uma
// poda imediata, para que um limite menor valha ja, e nao so na proxima poda periodica.
func (p *Persister) SetLimits(retention time.Duration, maxAlerts int) {
	p.mu.Lock()
	p.retention, p.maxAlerts = retention, maxAlerts
	p.mu.Unlock()
	select {
	case p.pruneNow <- struct{}{}:
	default: // ja ha uma poda pedida
	}
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
	p.prune()
	for {
		select {
		case a, ok := <-sub.C:
			if !ok {
				p.flush(batch)
				return
			}
			if batch = append(batch, a); len(batch) >= p.cfg.BatchSize {
				batch = p.flush(batch)
			}
		case <-flushTick.C:
			p.dropped.Store(sub.Dropped())
			batch = p.flush(batch)
		case <-pruneTick.C:
			p.prune()
		case <-p.pruneNow:
			p.prune()
		case <-ctx.Done():
			p.drain(sub, batch)
			return
		}
	}
}

// flush grava o lote e devolve o lote vazio, reaproveitando a memoria. Usa contexto
// proprio: a gravacao final nao pode ser cancelada pelo encerramento.
func (p *Persister) flush(batch []*psychoscopev1.Alerta) []*psychoscopev1.Alerta {
	if len(batch) == 0 {
		return batch
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.st.Insert(ctx, batch); err != nil {
		p.log.Error("falha ao gravar alertas", "n", len(batch), "err", err)
	}
	return batch[:0]
}

// prune aplica a retencao por idade e por quantidade.
func (p *Persister) prune() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p.mu.Lock()
	retention, maxAlerts := p.retention, p.maxAlerts
	p.mu.Unlock()
	var cutoff time.Time
	if retention > 0 {
		cutoff = time.Now().Add(-retention)
	}
	n, err := p.st.Prune(ctx, cutoff, maxAlerts)
	switch {
	case err != nil:
		p.log.Error("falha ao podar alertas", "err", err)
	case n > 0:
		p.log.Info("alertas antigos removidos", "n", n)
	}
}

// drain esvazia o que ja estava na fila da assinatura e faz a ultima gravacao.
func (p *Persister) drain(sub *alerts.Subscription, batch []*psychoscopev1.Alerta) {
	for {
		select {
		case a, ok := <-sub.C:
			if !ok {
				p.flush(batch)
				return
			}
			batch = append(batch, a)
		default:
			p.dropped.Store(sub.Dropped())
			p.flush(batch)
			return
		}
	}
}
