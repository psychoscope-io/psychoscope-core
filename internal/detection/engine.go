package detection

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Publisher recebe os alertas (satisfeito por *alerts.Bus).
type Publisher interface {
	Publish(*psychoscopev1.Alerta)
}

// EngineConfig parametriza o motor.
type EngineConfig struct {
	Window    time.Duration // duracao da janela deslizante
	MaxEvents int           // teto de eventos retidos
	QueueSize int           // fila de entrada; cheia => eventos descartados e contados
	Logger    *slog.Logger
}

// Stats sao os contadores do motor.
type Stats struct {
	Received   uint64 // aceitos na fila
	Dropped    uint64 // descartados por fila cheia
	Processed  uint64
	Alerts     uint64
	Suppressed uint64 // alertas evitados pelo cooldown
	RuleErrors uint64 // panics de regras contidos
	Window     int    // eventos retidos agora
}

type cooldownKey struct{ rule, key string }

// Engine consome eventos, mantem a janela e avalia as regras em uma unica goroutine.
type Engine struct {
	rules  []Rule
	window *Window
	pub    Publisher
	log    *slog.Logger
	in     chan *Event

	cooldown map[cooldownKey]time.Time // instante do ultimo alerta, no tempo dos eventos
	reconf   chan reconfig             // pedidos de Reconfigure, tratados dentro de Run
	snap     chan snapshotRequest      // pedidos de Snapshot, tratados dentro de Run

	received, dropped, processed, alerts, suppressed, ruleErrors atomic.Uint64
	windowLen                                                    atomic.Int64
}

// NewEngine cria o motor (ainda parado; chame Run).
func NewEngine(cfg EngineConfig, rules []Rule, pub Publisher) *Engine {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 200_000
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Engine{
		rules: rules, window: NewWindow(cfg.Window, cfg.MaxEvents), pub: pub, log: cfg.Logger,
		in: make(chan *Event, cfg.QueueSize), cooldown: map[cooldownKey]time.Time{}, reconf: make(chan reconfig),
		snap: make(chan snapshotRequest),
	}
}

// reconfig e um pedido de troca de regras e de duracao da janela.
type reconfig struct {
	rules []Rule
	span  time.Duration
	done  chan struct{}
}

// Reconfigure troca as regras e a duracao da janela com o motor rodando. A janela mantem os
// eventos retidos (so descarta o que sai da nova duracao). O estado das regras que continuam
// (cooldowns do motor e estado interno, como as series do beacon) passa para as instancias
// novas, exceto o das regras StateKeyed cuja chave de estado mudou (limiar ajustado): elas
// recomecam, e assim ajustar um limiar faz o alerta voltar na hora, enquanto mexer em outra
// regra, ou so em cooldown e listas de excecao, nao repete os alertas. Os eventos que
// ja estavam na fila sao avaliados antes, com as regras antigas. ctx limita so a entrega do
// pedido (motor parado ou travado): depois que o motor o aceita, a troca sempre termina
// (esvaziar a fila e limitado), entao esperamos por ela. Devolver um erro de contexto nesse
// ponto diria "nao aplicado" a quem ja teve o pedido aplicado.
func (e *Engine) Reconfigure(ctx context.Context, rules []Rule, span time.Duration) error {
	rc := reconfig{rules: rules, span: span, done: make(chan struct{})}
	select {
	case e.reconf <- rc:
	case <-ctx.Done():
		return ctx.Err()
	}
	<-rc.done
	return nil
}

// reconfigure roda na goroutine do motor, unica dona de rules, window e cooldown.
func (e *Engine) reconfigure(rc reconfig) {
	for n := len(e.in); n > 0; n-- { // so esta goroutine le da fila: os n eventos estao la
		e.process(<-e.in)
	}
	e.carryState(rc.rules)
	e.rules = rc.rules
	e.window.SetSpan(rc.span)
	e.windowLen.Store(int64(e.window.Len()))
	e.log.Info("motor reconfigurado", "regras", len(rc.rules), "janela", rc.span.String())
	close(rc.done)
}

// Submit enfileira um evento de rede sem nunca bloquear (chamado na goroutine de leitura
// da sessao IPC). Devolve false se a fila estava cheia e o evento foi descartado.
func (e *Engine) Submit(module string, n *psychoscopev1.EventoFluxoRede) bool {
	ev := NewEvent(module, n, time.Now())
	select {
	case e.in <- ev:
		e.received.Add(1)
		return true
	default:
		e.dropped.Add(1)
		return false
	}
}

// Stats devolve um retrato dos contadores.
func (e *Engine) Stats() Stats {
	return Stats{
		Received: e.received.Load(), Dropped: e.dropped.Load(), Processed: e.processed.Load(),
		Alerts: e.alerts.Load(), Suppressed: e.suppressed.Load(), RuleErrors: e.ruleErrors.Load(),
		Window: int(e.windowLen.Load()),
	}
}

// Run processa eventos ate ctx ser cancelado; ao cancelar, esvazia o que ja estava na fila.
func (e *Engine) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case ev := <-e.in:
					e.process(ev)
				default:
					return
				}
			}
		case ev := <-e.in:
			e.process(ev)
		case rc := <-e.reconf:
			e.reconfigure(rc)
		case req := <-e.snap:
			req.reply <- e.snapshot()
		}
	}
}

func (e *Engine) process(ev *Event) {
	e.window.Add(ev)
	e.windowLen.Store(int64(e.window.Len()))
	e.processed.Add(1)
	for _, r := range e.rules {
		e.evalRule(r, ev)
	}
	if len(e.cooldown) > 10_000 {
		e.purgeCooldowns()
	}
}

func (e *Engine) evalRule(r Rule, ev *Event) {
	defer func() {
		if p := recover(); p != nil {
			e.ruleErrors.Add(1)
			e.log.Error("regra falhou (panic contido)", "regra", r.Name(), "panic", fmt.Sprint(p))
		}
	}()

	var ck cooldownKey
	g, gated := r.(Gated)
	if gated {
		key, ok := g.Key(ev)
		if !ok {
			return
		}
		ck = cooldownKey{r.Name(), key}
		if last, active := e.cooldown[ck]; active && e.window.Now().Before(last.Add(g.Cooldown())) {
			e.suppressed.Add(1)
			return
		}
	}

	a := r.Eval(ev, e.window)
	if a == nil {
		return
	}
	if gated {
		e.cooldown[ck] = e.window.Now()
		if a.Contexto == nil {
			a.Contexto = map[string]string{}
		}
		a.Contexto["chave"] = ck.key
	}
	if a.Regra == "" {
		a.Regra = r.Name()
	}
	if a.IdModuloOrigem == "" {
		a.IdModuloOrigem = ev.Module
	}
	a.IdAlerta = newAlertID()
	a.Timestamp = timestamppb.Now()
	e.alerts.Add(1)
	e.log.Warn("alerta", "regra", a.Regra, "severidade", a.Severidade, "descricao", a.Descricao, "modulo", a.IdModuloOrigem)
	e.pub.Publish(a)
}

// purgeCooldowns descarta as supressoes vencidas e as de regras que nao existem mais; o prazo
// vem do cooldown atual da regra, ja que o mapa guarda so o instante do alerta.
func (e *Engine) purgeCooldowns() {
	cooldowns := e.gatedCooldowns()
	now := e.window.Now()
	for k, last := range e.cooldown {
		d, known := cooldowns[k.rule]
		if !known || !now.Before(last.Add(d)) {
			delete(e.cooldown, k)
		}
	}
}
