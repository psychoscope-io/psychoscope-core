package supervisor

import (
	"fmt"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Integracao com o servidor IPC: o Supervisor e o ipc.Authorizer (decide quem pode
// assumir o id de um modulo) e um ipc.Handler (acompanha conexao e desconexao).

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
	if pid == 0 || int32(pid) != cred.PID { //nolint:gosec // PID do kernel cabe em int32
		return fmt.Errorf("pid %d nao e o filho lancado de %q (filho=%d)", cred.PID, h.IdModulo, pid)
	}
	return nil
}

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
