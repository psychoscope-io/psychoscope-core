package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// ErrSessionClosed e devolvido a comandos pendentes quando a sessao cai.
	ErrSessionClosed = errors.New("ipc: sessao encerrada")
	// ErrNack indica que o modulo recusou o comando (RespostaComando.sucesso=false).
	ErrNack = errors.New("ipc: comando recusado pelo modulo")
	// ErrHeartbeatTimeout indica que o modulo parou de enviar mensagens.
	ErrHeartbeatTimeout = errors.New("ipc: heartbeat expirou")
)

const writeTimeout = 5 * time.Second

type cmdResult struct {
	resp *psychoscopev1.RespostaComando
	err  error
}

// Session e a conexao autenticada de um modulo.
type Session struct {
	ID            string
	Cred          PeerCred
	PID           uint32 // declarado no Hello e validado contra SO_PEERCRED
	ModuleVersion string
	ConnectedAt   time.Time

	srv  *Server
	conn net.Conn

	writeMu sync.Mutex

	mu         sync.Mutex
	pending    map[string]chan cmdResult
	lastSeen   time.Time
	lastStatus *psychoscopev1.StatusModulo
	closeErr   error
	closed     bool
	done       chan struct{}
}

func newSession(srv *Server, conn net.Conn, h *psychoscopev1.HelloModulo, cred PeerCred) *Session {
	now := time.Now()
	return &Session{
		ID: h.IdModulo, Cred: cred, PID: h.Pid, ModuleVersion: h.VersaoModulo,
		ConnectedAt: now, lastSeen: now,
		srv: srv, conn: conn,
		pending: map[string]chan cmdResult{},
		done:    make(chan struct{}),
	}
}

// Done e fechado quando a sessao termina.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err devolve o motivo do encerramento (nil para desconexao limpa ou sessao ativa).
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeErr
}

// LastSeen devolve o instante da ultima mensagem recebida do modulo.
func (s *Session) LastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeen
}

// LastStatus devolve o ultimo StatusModulo recebido (nil se nenhum).
func (s *Session) LastStatus() *psychoscopev1.StatusModulo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastStatus
}

func (s *Session) touch(st *psychoscopev1.StatusModulo) {
	s.mu.Lock()
	s.lastSeen = time.Now()
	if st != nil {
		s.lastStatus = st
	}
	s.mu.Unlock()
}

// Send envia uma mensagem ao modulo. Seguro para uso concorrente.
func (s *Session) Send(msg *psychoscopev1.MensagemIPC) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := WriteMessage(s.conn, msg); err != nil {
		s.Close(fmt.Errorf("escrita: %w", err))
		return err
	}
	return nil
}

// Command envia um ComandoControle e aguarda o ACK/NACK sincrono.
// Sem deadline em ctx, aplica o CommandTimeout do servidor. NACK devolve a
// resposta junto com um erro que satisfaz errors.Is(err, ErrNack).
func (s *Session) Command(ctx context.Context, acao psychoscopev1.ComandoControle_TipoAcao, params map[string]string) (*psychoscopev1.RespostaComando, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.srv.cfg.CommandTimeout)
		defer cancel()
	}

	id := NewID()
	ch := make(chan cmdResult, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()

	err := s.Send(&psychoscopev1.MensagemIPC{
		IdMensagem: NewID(), Timestamp: timestamppb.Now(),
		Payload: &psychoscopev1.MensagemIPC_Comando{Comando: &psychoscopev1.ComandoControle{
			IdComando: id, Acao: acao, Parametros: params,
		}},
	})
	if err != nil {
		return nil, err
	}

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if !r.resp.Sucesso {
			return r.resp, fmt.Errorf("%w: %s", ErrNack, r.resp.MensagemErro)
		}
		return r.resp, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("comando %s (%s): %w", id, acao, ctx.Err())
	case <-s.done:
		return nil, ErrSessionClosed
	}
}

// deliver entrega uma RespostaComando ao Command pendente. Retorna false se
// id_comando_referencia nao corresponde a nenhum comando em espera.
func (s *Session) deliver(r *psychoscopev1.RespostaComando) bool {
	s.mu.Lock()
	ch, ok := s.pending[r.IdComandoReferencia]
	s.mu.Unlock()
	if ok {
		select {
		case ch <- cmdResult{resp: r}:
		default:
		}
	}
	return ok
}

// Close encerra a sessao (idempotente). err e registrado como motivo.
func (s *Session) Close(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.closeErr = err
	s.mu.Unlock()
	close(s.done)
	_ = s.conn.Close()
}
