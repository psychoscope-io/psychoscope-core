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
	mu      sync.Mutex
	subs    map[*Subscription]struct{}
	history []*psychoscopev1.Alerta // anel dos ultimos alertas, do mais antigo ao mais novo
	histCap int
}

// DefaultHistory e a quantidade de alertas recentes retidos em memoria.
const DefaultHistory = 256

// Subscription e uma assinatura ativa.
type Subscription struct {
	C       <-chan *psychoscopev1.Alerta
	ch      chan *psychoscopev1.Alerta
	bus     *Bus
	dropped atomic.Uint64
	once    sync.Once
}

// NewBus cria um barramento vazio que retem os DefaultHistory alertas mais recentes.
func NewBus() *Bus { return NewBusWithHistory(DefaultHistory) }

// NewBusWithHistory cria um barramento que retem os n alertas mais recentes (0 = sem historico).
func NewBusWithHistory(n int) *Bus {
	return &Bus{subs: map[*Subscription]struct{}{}, histCap: max(n, 0)}
}

// Recent devolve uma copia do historico, do mais antigo ao mais novo.
func (b *Bus) Recent() []*psychoscopev1.Alerta {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*psychoscopev1.Alerta(nil), b.history...)
}

// Subscribe cria uma assinatura com buffer de tamanho buffer (minimo 1).
func (b *Bus) Subscribe(buffer int) *Subscription { return b.subscribe(buffer, false) }

// SubscribeWithHistory e como Subscribe, mas a assinatura ja nasce com o historico
// retido (atomicamente: sem lacunas nem duplicatas em relacao ao que vem depois).
func (b *Bus) SubscribeWithHistory(buffer int) *Subscription { return b.subscribe(buffer, true) }

func (b *Bus) subscribe(buffer int, replay bool) *Subscription {
	if buffer < 1 {
		buffer = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var past []*psychoscopev1.Alerta
	if replay {
		past = b.history
	}
	ch := make(chan *psychoscopev1.Alerta, buffer+len(past))
	for _, a := range past {
		ch <- a
	}
	s := &Subscription{C: ch, ch: ch, bus: b}
	b.subs[s] = struct{}{}
	return s
}

// Publish entrega a a todos os assinantes, descartando para os que estao cheios.
func (b *Bus) Publish(a *psychoscopev1.Alerta) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.histCap > 0 {
		if len(b.history) == b.histCap {
			copy(b.history, b.history[1:])
			b.history = b.history[:b.histCap-1]
		}
		b.history = append(b.history, a)
	}
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
