package supervisor

import (
	"context"
	"errors"
	"fmt"

	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Modulos External: o systemd lanca e reinicia o processo (com usuario e capabilities proprios),
// e o Core nunca recebe privilegio nenhum. O supervisor so autentica e acompanha a conexao.

// ErrExternalOffline: o modulo External nao esta conectado, e quem o inicia e o systemd.
var ErrExternalOffline = errors.New("supervisor: modulo externo sem sessao; inicie-o pelo systemd (systemctl start <unidade do modulo>)")

// authorizeExternal exige o UID exato do usuario configurado para o modulo. Sem UID resolvido
// (Options.ExternalUIDs incompleto) recusa: na duvida, fail closed. O PID nao entra: o Core nao
// lancou o processo.
func authorizeExternal(m *managed, id string, cred ipc.PeerCred) error {
	want, ok := m.externalUID()
	if !ok {
		return fmt.Errorf("modulo externo %q sem uid configurado", id)
	}
	if cred.UID != want {
		return fmt.Errorf("uid %d nao e o usuario %q do modulo externo %q (uid %d)", cred.UID, m.spec.User, id, want)
	}
	return nil
}

// externalStateAfterDisconnect: apos um ENCERRAR confirmado o modulo esta encerrado; senao o
// systemd o reinicia e o estado volta a "iniciando" (aguardando a reconexao).
func externalStateAfterDisconnect(stopping bool) psychoscopev1.EstadoModulo {
	if stopping {
		return psychoscopev1.EstadoModulo_ESTADO_ENCERRADO
	}
	return psychoscopev1.EstadoModulo_ESTADO_INICIANDO
}

// stopExternal pede o ENCERRAR por IPC. Quem decide reiniciar o processo depois e o systemd
// (Restart=on-failure: uma saida limpa fica parada).
func (s *Supervisor) stopExternal(ctx context.Context, m *managed) error {
	m.mu.Lock()
	sess := m.sess
	m.mu.Unlock()
	if sess == nil {
		return ErrExternalOffline
	}
	m.set(func() { m.stopping = true })
	if _, err := sess.Command(ctx, psychoscopev1.ComandoControle_ENCERRAR, nil); err != nil {
		m.set(func() { m.stopping = false })
		return err
	}
	return nil
}

func (m *managed) externalUID() (uint32, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.uid, m.hasUID
}
