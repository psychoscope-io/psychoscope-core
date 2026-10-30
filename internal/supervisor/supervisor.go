// Package supervisor gerencia o ciclo de vida dos modulos filhos: lanca via
// os/exec, reinicia com backoff exponencial, vigia a conexao IPC (healthcheck)
// e encerra de forma graciosa (ENCERRAR -> SIGTERM -> SIGKILL).
//
// Contratos com o modulo:
//   - o filho e lancado com ambiente minimo (PATH + spec.Env) mais
//     PSYCHOSCOPE_SOCKET e PSYCHOSCOPE_MODULE_ID;
//   - o PID que conecta ao socket precisa ser o do filho lancado (checado via
//     SO_PEERCRED); portanto o binario deve fazer exec direto, sem wrapper que
//     deixe o conector como processo-neto;
//   - o filho deve enviar StatusModulo periodicamente (heartbeat) e reconectar
//     se a conexao cair.
//
// Um modulo External nao e lancado aqui: o systemd o mantem, com as proprias capabilities e
// usuario, e o supervisor so o autentica (UID do kernel) e acompanha a conexao (external.go).
package supervisor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

var (
	ErrUnknownModule = errors.New("supervisor: modulo desconhecido")
	ErrNotConnected  = errors.New("supervisor: modulo sem sessao IPC ativa")
	ErrStopped       = errors.New("supervisor: modulo encerrado; use resume para reinicia-lo")
)

// Variaveis (e nao constantes) para que os testes possam encurtar os prazos.
var (
	watchdogTick  = 100 * time.Millisecond
	termGrace     = 3 * time.Second // espera por saida apos SIGTERM, antes de SIGKILL
	shutdownCmdTO = 2 * time.Second // prazo do ACK do ENCERRAR via IPC
)

// Options configura o supervisor.
type Options struct {
	Specs          []config.ModuleSpec
	SocketPath     string // repassado aos filhos em PSYCHOSCOPE_SOCKET
	UIDs           ipc.UIDPolicy
	AllowUnmanaged bool
	ExternalUIDs   map[string]uint32 // id do modulo External -> UID do usuario do servico
	Logger         *slog.Logger
}

// Info e o retrato de um modulo supervisionado.
type Info struct {
	ID          string
	State       psychoscopev1.EstadoModulo
	PID         int
	Restarts    uint32
	LastContact time.Time
	LastStatus  *psychoscopev1.StatusModulo
	LastError   string
	// ModuleVersion e ConnectedSince vem da conexao ativa (HelloModulo e instante do handshake);
	// ficam vazios enquanto o modulo nao esta conectado.
	ModuleVersion  string
	ConnectedSince time.Time
}

// Supervisor implementa ipc.Authorizer e ipc.Handler (estado de conexao dos modulos).
type Supervisor struct {
	opt   Options
	log   *slog.Logger
	mods  map[string]*managed
	order []string

	// mu protege runCtx e closing e serializa o lancamento de goroutines de
	// modulo, para que wg.Add nunca corra com wg.Wait (em Run).
	mu      sync.Mutex
	runCtx  context.Context // nil ate Run
	closing bool            // Run saiu de <-ctx.Done: nada novo pode ser lancado
	wg      sync.WaitGroup
}

// cycle e uma execucao da goroutine de um modulo (do lancamento ate Stop ou
// cancelamento). Um modulo encerrado ganha um cycle novo ao ser reiniciado.
type cycle struct {
	stopOnce sync.Once
	stopCh   chan struct{} // fechado por stop: sem novos restarts
	finished chan struct{} // fechado quando a goroutine do modulo termina
}

func newCycle() *cycle {
	return &cycle{stopCh: make(chan struct{}), finished: make(chan struct{})}
}

func (c *cycle) stop() { c.stopOnce.Do(func() { close(c.stopCh) }) }

func (c *cycle) isFinished() bool {
	select {
	case <-c.finished:
		return true
	default:
		return false
	}
}

type managed struct {
	spec config.ModuleSpec

	mu          sync.Mutex
	cycle       *cycle
	state       psychoscopev1.EstadoModulo
	pid         int
	restarts    uint32
	lastErr     string
	lastContact time.Time
	lastDisc    time.Time
	sess        *ipc.Session
	paused      bool
	uid         uint32 // External: UID do usuario do servico
	hasUID      bool
	stopping    bool // External: ENCERRAR foi confirmado; a proxima desconexao e esperada
}

// New cria o supervisor (nada e lancado ate Run).

func New(opt Options) *Supervisor {
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Supervisor{opt: opt, log: opt.Logger, mods: map[string]*managed{}}
	for _, sp := range opt.Specs {
		uid, hasUID := opt.ExternalUIDs[sp.ID]
		state := psychoscopev1.EstadoModulo_ESTADO_DESCONHECIDO
		if sp.External {
			state = psychoscopev1.EstadoModulo_ESTADO_INICIANDO // aguardando o systemd e a conexao
		}
		s.mods[sp.ID] = &managed{spec: sp, cycle: newCycle(), uid: uid, hasUID: hasUID && sp.External, state: state}
		s.order = append(s.order, sp.ID)
	}
	return s
}

// Run lanca todos os modulos e bloqueia ate ctx ser cancelado e todos terem
// sido encerrados graciosamente. Modulos parados individualmente via Stop nao
// fazem Run retornar.
func (s *Supervisor) Run(ctx context.Context) {
	s.mu.Lock()
	s.runCtx = ctx
	for _, id := range s.order {
		m := s.mods[id]
		if m.spec.External {
			continue // mantido pelo systemd: so espera a conexao
		}
		s.launch(ctx, m, m.currentCycle())
	}
	s.mu.Unlock()
	<-ctx.Done()
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	s.wg.Wait()
}

// launch inicia a goroutine do modulo para o ciclo cy. Exige s.mu.
func (s *Supervisor) launch(ctx context.Context, m *managed, cy *cycle) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runModule(ctx, m, cy)
	}()
}

// restart relanca um modulo encerrado por Stop. Se o modulo ainda esta
// rodando (mesmo sem sessao) devolve ErrNotConnected.
func (s *Supervisor) restart(m *managed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runCtx == nil || s.closing || s.runCtx.Err() != nil {
		return errors.New("supervisor: nucleo nao esta em execucao; nao e possivel reiniciar o modulo")
	}
	if !m.currentCycle().isFinished() {
		return ErrNotConnected
	}
	cy := newCycle()
	m.set(func() { m.cycle = cy })
	s.launch(s.runCtx, m, cy)
	return nil
}

// Stop encerra o modulo id graciosamente e o impede de reiniciar.
func (s *Supervisor) Stop(ctx context.Context, id string) error {
	m, ok := s.mods[id]
	if !ok {
		return ErrUnknownModule
	}
	if m.spec.External {
		return s.stopExternal(ctx, m)
	}
	cy := m.currentCycle()
	cy.stop()
	select {
	case <-cy.finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Command executa uma acao de controle sobre o modulo id.
// ENCERRAR e tratada pelo supervisor (inclui escalonamento de sinais);
// RETOMAR de um modulo encerrado o relanca (o retorno nao espera a conexao);
// as demais viram comandos IPC sincronos (ACK/NACK).
func (s *Supervisor) Command(ctx context.Context, id string, acao psychoscopev1.ComandoControle_TipoAcao, params map[string]string) error {
	m, ok := s.mods[id]
	if !ok {
		return ErrUnknownModule
	}
	if acao == psychoscopev1.ComandoControle_ENCERRAR {
		return s.Stop(ctx, id)
	}
	if acao == psychoscopev1.ComandoControle_ACAO_DESCONHECIDA {
		return errors.New("supervisor: acao desconhecida")
	}
	m.mu.Lock()
	sess := m.sess
	m.mu.Unlock()
	if sess == nil && m.spec.External {
		return ErrExternalOffline
	}
	if sess == nil {
		if !m.currentCycle().isFinished() {
			return ErrNotConnected
		}
		if acao == psychoscopev1.ComandoControle_RETOMAR {
			return s.restart(m)
		}
		return ErrStopped
	}
	if _, err := sess.Command(ctx, acao, params); err != nil {
		return err
	}
	switch acao {
	case psychoscopev1.ComandoControle_PAUSAR:
		m.mu.Lock()
		m.paused = true
		m.mu.Unlock()
	case psychoscopev1.ComandoControle_RETOMAR:
		m.mu.Lock()
		m.paused = false
		m.mu.Unlock()
	}
	return nil
}

// List devolve o retrato de todos os modulos na ordem de configuracao.
func (s *Supervisor) List() []Info {
	out := make([]Info, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.mods[id].info())
	}
	return out
}

// Get devolve o retrato do modulo id.
func (s *Supervisor) Get(id string) (Info, bool) {
	m, ok := s.mods[id]
	if !ok {
		return Info{}, false
	}
	return m.info(), true
}

// IDs devolve os IDs configurados, ordenados.
func (s *Supervisor) IDs() []string {
	ids := append([]string(nil), s.order...)
	sort.Strings(ids)
	return ids
}

func (m *managed) info() Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	in := Info{ID: m.spec.ID, State: m.state, PID: m.pid, Restarts: m.restarts, LastContact: m.lastContact, LastError: m.lastErr}
	if m.sess != nil {
		in.LastContact = m.sess.LastSeen()
		in.LastStatus = m.sess.LastStatus()
		in.ModuleVersion, in.ConnectedSince = m.sess.ModuleVersion, m.sess.ConnectedAt
		if m.paused {
			in.State = psychoscopev1.EstadoModulo_ESTADO_PAUSADO
		}
	}
	return in
}

func (m *managed) set(f func()) {
	m.mu.Lock()
	f()
	m.mu.Unlock()
}

func (m *managed) currentCycle() *cycle {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cycle
}

func (m *managed) setState(st psychoscopev1.EstadoModulo) { m.set(func() { m.state = st }) }
