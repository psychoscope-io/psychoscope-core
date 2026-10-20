package ipc

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Handshake: leitura do Hello, validacao (versao, id, PID real, autorizacao),
// registro da sessao e resposta de aceite ou recusa.

func (s *Server) reject(conn net.Conn, reason string) {
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_ = WriteMessage(conn, &psychoscopev1.MensagemIPC{
		IdMensagem: NewID(), Timestamp: timestamppb.Now(),
		Payload: &psychoscopev1.MensagemIPC_HelloResposta{HelloResposta: &psychoscopev1.HelloResposta{
			Aceito: false, MensagemErro: reason, VersaoCore: s.cfg.CoreVersion,
		}},
	})
}

var (
	errClosing   = errors.New("servidor encerrando")
	errDuplicate = errors.New("sessao duplicada")
)

// handshake valida credenciais e Hello e registra a sessao. Em caso de erro a
// conexao ja foi respondida/descartada; o chamador so precisa fecha-la.
func (s *Server) handshake(conn *net.UnixConn) (*Session, error) {
	cred, h, err := s.readHello(conn)
	if err != nil {
		return nil, err
	}
	if public, cause := s.vetHello(h, cred); cause != nil {
		return nil, s.deny(conn, h, cred, public, cause)
	}
	sess := newSession(s, conn, h, cred)
	switch err := s.register(sess); {
	case errors.Is(err, errClosing):
		return nil, errClosing
	case errors.Is(err, errDuplicate):
		return nil, s.deny(conn, h, cred, "modulo ja conectado", errDuplicate)
	}
	if err := s.acceptHello(conn); err != nil {
		s.unregister(sess)
		return nil, fmt.Errorf("enviando HelloResposta: %w", err)
	}
	return sess, nil
}

// readHello le as credenciais do peer (SO_PEERCRED) e a primeira mensagem, que tem de ser Hello.
func (s *Server) readHello(conn *net.UnixConn) (PeerCred, *psychoscopev1.HelloModulo, error) {
	cred, err := PeerCredOf(conn)
	if err != nil {
		return cred, nil, fmt.Errorf("credenciais do peer: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HelloTimeout))
	m, err := ReadMessage(conn, 0)
	if err != nil {
		return cred, nil, fmt.Errorf("lendo Hello (pid=%d uid=%d): %w", cred.PID, cred.UID, err)
	}
	h := m.GetHello()
	if h == nil {
		return cred, nil, fmt.Errorf("primeira mensagem nao e Hello (pid=%d uid=%d)", cred.PID, cred.UID)
	}
	return cred, h, nil
}

// vetHello valida o Hello e autoriza o modulo. Em caso de recusa devolve a mensagem
// publica (enviada ao modulo) e a causa (apenas para o log).
func (s *Server) vetHello(h *psychoscopev1.HelloModulo, cred PeerCred) (public string, cause error) {
	switch {
	case !config.ValidModuleID(h.IdModulo):
		return "id_modulo invalido", errors.New("id_modulo invalido")
	case h.VersaoProtocolo != ProtocolVersion:
		return fmt.Sprintf("versao de protocolo nao suportada (core=%d)", ProtocolVersion),
			fmt.Errorf("versao_protocolo=%d", h.VersaoProtocolo)
	case int64(h.Pid) != int64(cred.PID):
		return "pid declarado difere do peer", fmt.Errorf("pid declarado=%d real=%d", h.Pid, cred.PID)
	}
	if err := s.cfg.Auth.Authorize(h, cred); err != nil {
		return "nao autorizado", err
	}
	return "", nil
}

// deny responde a recusa ao modulo e devolve o erro (completo) para o log.
func (s *Server) deny(conn *net.UnixConn, h *psychoscopev1.HelloModulo, cred PeerCred, public string, cause error) error {
	s.reject(conn, public)
	return fmt.Errorf("hello rejeitado (modulo=%q pid=%d uid=%d): %w", h.IdModulo, cred.PID, cred.UID, cause)
}

// register inclui a sessao no mapa; devolve errClosing, errDuplicate ou nil.
func (s *Server) register(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return errClosing
	}
	if _, dup := s.sessions[sess.ID]; dup {
		return errDuplicate
	}
	s.sessions[sess.ID] = sess
	return nil
}

// acceptHello envia o HelloResposta de aceite com o intervalo de status esperado.
func (s *Server) acceptHello(conn *net.UnixConn) error {
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return WriteMessage(conn, &psychoscopev1.MensagemIPC{
		IdMensagem: NewID(), Timestamp: timestamppb.Now(),
		Payload: &psychoscopev1.MensagemIPC_HelloResposta{HelloResposta: &psychoscopev1.HelloResposta{
			Aceito: true, VersaoCore: s.cfg.CoreVersion,
			IntervaloStatusSeg: uint32(max(1, int(s.cfg.StatusInterval/time.Second))), //nolint:gosec // intervalo validado em Config.Validate
		}},
	})
}
