// Package alerts implementa o barramento de alertas (pub/sub em memoria) entre o
// motor de deteccao e os assinantes (canal de controle / TUI).
package alerts

import (
	"sync"
	"sync/atomic"

	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
)

// Bus distribui alertas a todos os assinantes sem nunca bloquear o publicador:
// um assinante lento perde alertas (contabilizados em Dropped).
type Bus struct {
	mu   sync.Mutex
	subs map[*Subscription]struct{}
}

// Subscription e uma assinatura ativa.
type Subscription struct {
	C       <-chan *psychoscopev1.Alerta
	ch      chan *psychoscopev1.Alerta
	bus     *Bus
	dropped atomic.Uint64
	once    sync.Once
}

// NewBus cria um barramento vazio.
func NewBus() *Bus { return &Bus{subs: map[*Subscription]struct{}{}} }

// Subscribe cria uma assinatura com buffer de tamanho buffer (minimo 1).
func (b *Bus) Subscribe(buffer int) *Subscription {
	if buffer < 1 {
		buffer = 1
	}
	ch := make(chan *psychoscopev1.Alerta, buffer)
	s := &Subscription{C: ch, ch: ch, bus: b}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// Publish entrega a a todos os assinantes, descartando para os que estao cheios.
func (b *Bus) Publish(a *psychoscopev1.Alerta) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.subs {
		select {
		case s.ch <- a:
		default:
			s.dropped.Add(1)
		}
	}
}

// Dropped devolve quantos alertas esta assinatura perdeu por estar lenta.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// Close cancela a assinatura e fecha C. Idempotente.
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.bus.mu.Lock()
		delete(s.bus.subs, s)
		s.bus.mu.Unlock()
		close(s.ch)
	})
}
