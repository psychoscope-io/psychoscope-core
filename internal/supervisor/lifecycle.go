package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Ciclo de vida de um processo filho: lancamento, vigilancia (watchdog de conexao),
// backoff de reinicio e parada em escalada (ENCERRAR -> SIGTERM -> SIGKILL).

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
