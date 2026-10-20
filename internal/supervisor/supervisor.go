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
}

// Supervisor implementa ipc.Authorizer e ipc.Handler (estado de conexao dos modulos).
type Supervisor struct {
	opt   Options
	log   *slog.Logger
	mods  map[string]*managed
	order []string
}

type managed struct {
	spec config.ModuleSpec

	stopOnce sync.Once
	stopCh   chan struct{} // fechado por Stop: sem novos restarts
	finished chan struct{} // fechado quando a goroutine do modulo termina

	mu          sync.Mutex
	state       psychoscopev1.EstadoModulo
	pid         int
	restarts    uint32
	lastErr     string
	lastContact time.Time
	lastDisc    time.Time
	sess        *ipc.Session
	paused      bool
}

// New cria o supervisor (nada e lancado ate Run).

func New(opt Options) *Supervisor {
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Supervisor{opt: opt, log: opt.Logger, mods: map[string]*managed{}}
	for _, sp := range opt.Specs {
		s.mods[sp.ID] = &managed{
			spec: sp, stopCh: make(chan struct{}), finished: make(chan struct{}),
			state: psychoscopev1.EstadoModulo_ESTADO_DESCONHECIDO,
		}
		s.order = append(s.order, sp.ID)
	}
	return s
}

// Run lanca todos os modulos e bloqueia ate ctx ser cancelado e todos terem
// sido encerrados graciosamente. Modulos parados individualmente via Stop nao
// fazem Run retornar.
func (s *Supervisor) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, id := range s.order {
		m := s.mods[id]
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runModule(ctx, m)
		}()
	}
	<-ctx.Done()
	wg.Wait()
}

// Stop encerra o modulo id graciosamente e o impede de reiniciar.
func (s *Supervisor) Stop(ctx context.Context, id string) error {
	m, ok := s.mods[id]
	if !ok {
		return ErrUnknownModule
	}
	m.stopOnce.Do(func() { close(m.stopCh) })
	select {
	case <-m.finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Command executa uma acao de controle sobre o modulo id.
// ENCERRAR e tratada pelo supervisor (inclui escalonamento de sinais);
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
	if sess == nil {
		return ErrNotConnected
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

func (m *managed) setState(st psychoscopev1.EstadoModulo) { m.set(func() { m.state = st }) }
