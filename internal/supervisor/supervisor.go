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
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"sync"
	"syscall"
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

// ---- ipc.Authorizer ----

// Authorize aceita apenas UIDs permitidos e, para modulos gerenciados, apenas o
// PID do filho lancado por este supervisor.
func (s *Supervisor) Authorize(h *psychoscopev1.HelloModulo, cred ipc.PeerCred) error {
	if !s.opt.UIDs.Allows(cred.UID) {
		return fmt.Errorf("uid %d nao permitido", cred.UID)
	}
	m, ok := s.mods[h.IdModulo]
	if !ok {
		if s.opt.AllowUnmanaged {
			return nil
		}
		return fmt.Errorf("modulo %q nao esta configurado", h.IdModulo)
	}
	m.mu.Lock()
	pid := m.pid
	m.mu.Unlock()
	if pid == 0 || int32(pid) != cred.PID {
		return fmt.Errorf("pid %d nao e o filho lancado de %q (filho=%d)", cred.PID, h.IdModulo, pid)
	}
	return nil
}

// ---- ipc.Handler ----

func (s *Supervisor) OnConnect(sess *ipc.Session) {
	m, ok := s.mods[sess.ID]
	if !ok {
		return
	}
	m.set(func() {
		m.sess = sess
		m.paused = false
		m.state = psychoscopev1.EstadoModulo_ESTADO_CONECTADO
		m.lastContact = time.Now()
	})
}

func (s *Supervisor) OnTelemetry(*ipc.Session, *psychoscopev1.EventoTelemetria) {}
func (s *Supervisor) OnStatus(*ipc.Session, *psychoscopev1.StatusModulo)        {}

func (s *Supervisor) OnDisconnect(sess *ipc.Session, err error) {
	m, ok := s.mods[sess.ID]
	if !ok {
		return
	}
	m.set(func() {
		if m.sess != sess {
			return
		}
		m.sess = nil
		m.paused = false
		m.lastDisc = time.Now()
		m.lastContact = sess.LastSeen()
		if err != nil {
			m.lastErr = err.Error()
		}
		if m.pid != 0 && m.state == psychoscopev1.EstadoModulo_ESTADO_CONECTADO {
			m.state = psychoscopev1.EstadoModulo_ESTADO_INICIANDO // vivo, aguardando reconexao
		}
	})
}

// ---- ciclo de vida ----

func nextBackoff(cur, max time.Duration) time.Duration {
	if n := cur * 2; n < max {
		return n
	}
	return max
}

func (m *managed) stopping(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	select {
	case <-m.stopCh:
		return true
	default:
		return false
	}
}

func (s *Supervisor) runModule(ctx context.Context, m *managed) {
	defer close(m.finished)
	backoff := m.spec.MinBackoff
	for {
		if m.stopping(ctx) {
			m.setState(psychoscopev1.EstadoModulo_ESTADO_ENCERRADO)
			return
		}
		m.setState(psychoscopev1.EstadoModulo_ESTADO_INICIANDO)

		started := time.Now()
		cmd := s.buildCmd(m.spec)
		if err := cmd.Start(); err != nil {
			s.log.Error("falha ao lancar modulo", "modulo", m.spec.ID, "err", err)
			m.set(func() {
				m.lastErr = "start: " + err.Error()
				m.state = psychoscopev1.EstadoModulo_ESTADO_FALHOU
			})
		} else {
			m.set(func() { m.pid = cmd.Process.Pid })
			s.log.Info("modulo lancado", "modulo", m.spec.ID, "pid", cmd.Process.Pid)
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()

			stopped, werr := s.supervise(ctx, m, cmd, exited, started)
			m.set(func() { m.pid = 0; m.sess = nil })
			if stopped {
				m.setState(psychoscopev1.EstadoModulo_ESTADO_ENCERRADO)
				s.log.Info("modulo encerrado", "modulo", m.spec.ID)
				return
			}
			m.set(func() { m.lastErr = werr })
			s.log.Warn("modulo terminou; reiniciando", "modulo", m.spec.ID, "motivo", werr)
			if time.Since(started) >= m.spec.StableAfter {
				backoff = m.spec.MinBackoff
			}
			m.setState(psychoscopev1.EstadoModulo_ESTADO_REINICIANDO)
		}

		wait := backoff
		backoff = nextBackoff(backoff, m.spec.MaxBackoff)
		m.set(func() { m.restarts++ })
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
		case <-m.stopCh:
		}
		t.Stop()
	}
}

func (s *Supervisor) buildCmd(sp config.ModuleSpec) *exec.Cmd {
	cmd := exec.Command(sp.Path, sp.Args...)
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"PSYCHOSCOPE_SOCKET=" + s.opt.SocketPath,
		"PSYCHOSCOPE_MODULE_ID=" + sp.ID,
	}, sp.Env...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // grupo proprio: sinais atingem toda a arvore do filho
	cmd.Stdout = &lineLogger{log: s.log.With("modulo", sp.ID), stream: "stdout"}
	cmd.Stderr = &lineLogger{log: s.log.With("modulo", sp.ID), stream: "stderr"}
	return cmd
}

// supervise vigia o processo ate ele sair. stopped=true quando a saida foi
// provocada por Stop/cancelamento (sem restart); caso contrario devolve o motivo.
func (s *Supervisor) supervise(ctx context.Context, m *managed, cmd *exec.Cmd, exited <-chan error, started time.Time) (stopped bool, reason string) {
	tick := time.NewTicker(watchdogTick)
	defer tick.Stop()
	killed := false
	for {
		select {
		case err := <-exited:
			if killed {
				return false, m.lastError()
			}
			return false, describeExit(err)
		case <-ctx.Done():
			s.terminate(m, cmd, exited)
			return true, ""
		case <-m.stopCh:
			s.terminate(m, cmd, exited)
			return true, ""
		case <-tick.C:
			if killed {
				continue
			}
			m.mu.Lock()
			ref := started
			if m.lastDisc.After(ref) {
				ref = m.lastDisc
			}
			late := m.sess == nil && time.Since(ref) > m.spec.ConnectTimeout
			if late {
				m.lastErr = fmt.Sprintf("nao conectou ao socket em %v", m.spec.ConnectTimeout)
			}
			m.mu.Unlock()
			if late {
				s.log.Warn("modulo nao conectou a tempo; matando", "modulo", m.spec.ID)
				signalGroup(cmd, syscall.SIGKILL)
				killed = true
			}
		}
	}
}

func (m *managed) lastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

// terminate: ENCERRAR via IPC -> espera StopGrace -> SIGTERM -> espera termGrace -> SIGKILL.
func (s *Supervisor) terminate(m *managed, cmd *exec.Cmd, exited <-chan error) {
	m.mu.Lock()
	sess := m.sess
	m.mu.Unlock()
	if sess != nil {
		cctx, cancel := context.WithTimeout(context.Background(), shutdownCmdTO)
		if _, err := sess.Command(cctx, psychoscopev1.ComandoControle_ENCERRAR, nil); err != nil {
			s.log.Warn("ENCERRAR nao confirmado", "modulo", m.spec.ID, "err", err)
		}
		cancel()
	}
	if waitExit(exited, m.spec.StopGrace) {
		return
	}
	s.log.Warn("modulo ignorou ENCERRAR; enviando SIGTERM", "modulo", m.spec.ID)
	signalGroup(cmd, syscall.SIGTERM)
	if waitExit(exited, termGrace) {
		return
	}
	s.log.Warn("modulo ignorou SIGTERM; enviando SIGKILL", "modulo", m.spec.ID)
	signalGroup(cmd, syscall.SIGKILL)
	<-exited
}

func waitExit(exited <-chan error, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-exited:
		return true
	case <-t.C:
		return false
	}
}

func signalGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd.Process == nil {
		return
	}
	// -pid = grupo criado por Setpgid; ESRCH (ja saiu) e esperado e ignorado.
	_ = syscall.Kill(-cmd.Process.Pid, sig)
}

func describeExit(err error) string {
	if err == nil {
		return "saiu com status 0"
	}
	return err.Error()
}
