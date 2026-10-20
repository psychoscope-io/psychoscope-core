package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProtocolVersion e a versao do protocolo IPC aceita no Hello.
const ProtocolVersion = 1

// heartbeatMisses: quantos intervalos de status sem nenhuma mensagem tolerar.
const heartbeatMisses = 3

// Authorizer decide se um modulo que passou no Hello basico pode ser aceito.
// Um erro rejeita a conexao (a mensagem vai ao modulo, portanto nao deve vazar detalhes internos).
type Authorizer interface {
	Authorize(h *psychoscopev1.HelloModulo, cred PeerCred) error
}

// Handler recebe os eventos das sessoes. Os metodos rodam na goroutine de leitura
// da sessao e NAO devem bloquear.
type Handler interface {
	OnConnect(s *Session)
	OnTelemetry(s *Session, ev *psychoscopev1.EventoTelemetria)
	OnStatus(s *Session, st *psychoscopev1.StatusModulo)
	OnDisconnect(s *Session, err error)
}

// NopHandler ignora todos os eventos.
type NopHandler struct{}

func (NopHandler) OnConnect(*Session)                                    {}
func (NopHandler) OnTelemetry(*Session, *psychoscopev1.EventoTelemetria) {}
func (NopHandler) OnStatus(*Session, *psychoscopev1.StatusModulo)        {}
func (NopHandler) OnDisconnect(*Session, error)                          {}

// ServerConfig parametriza o servidor de modulos.
type ServerConfig struct {
	Path           string
	Mode           os.FileMode
	CoreVersion    string
	StatusInterval time.Duration // enviado ao modulo; 3x sem mensagens derruba a sessao
	CommandTimeout time.Duration
	HelloTimeout   time.Duration // padrao 5s
	MaxHandshakes  int           // handshakes simultaneos; padrao 32
	Auth           Authorizer
	Handler        Handler
	Logger         *slog.Logger
}

// Server aceita conexoes de modulos em core.sock.
type Server struct {
	cfg ServerConfig
	log *slog.Logger
	ln  *net.UnixListener

	hs chan struct{} // semaforo de handshakes

	mu       sync.Mutex
	sessions map[string]*Session
	conns    map[net.Conn]struct{} // conexoes em handshake, para encerrar no Shutdown
	wg       sync.WaitGroup
	closing  bool
}

// NewServer valida cfg e cria o servidor (ainda sem escutar).
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Path == "" || cfg.Auth == nil {
		return nil, errors.New("ipc: Path e Auth sao obrigatorios")
	}
	if cfg.Mode == 0 {
		cfg.Mode = 0o660
	}
	if cfg.StatusInterval <= 0 {
		cfg.StatusInterval = 5 * time.Second
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 5 * time.Second
	}
	if cfg.HelloTimeout <= 0 {
		cfg.HelloTimeout = 5 * time.Second
	}
	if cfg.MaxHandshakes <= 0 {
		cfg.MaxHandshakes = 32
	}
	if cfg.Handler == nil {
		cfg.Handler = NopHandler{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{
		cfg: cfg, log: cfg.Logger,
		hs:       make(chan struct{}, cfg.MaxHandshakes),
		sessions: map[string]*Session{},
		conns:    map[net.Conn]struct{}{},
	}, nil
}

// Listen abre o socket.
func (s *Server) Listen() error {
	ln, err := ListenUnix(s.cfg.Path, s.cfg.Mode, s.log)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Serve aceita conexoes ate ctx ser cancelado ou Shutdown ser chamado.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case s.hs <- struct{}{}:
		default:
			s.log.Warn("handshakes simultaneos demais; conexao recusada")
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			<-s.hs
			conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Shutdown para de aceitar, encerra todas as sessoes e aguarda as goroutines.
func (s *Server) Shutdown() {
	s.mu.Lock()
	s.closing = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	sess := make([]*Session, 0, len(s.sessions))
	for _, x := range s.sessions {
		sess = append(sess, x)
	}
	s.mu.Unlock()
	for _, x := range sess {
		x.Close(nil)
	}
	s.wg.Wait()
}

// Session devolve a sessao ativa do modulo id.
func (s *Server) Session(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[id]
	return x, ok
}

// Sessions lista as sessoes ativas ordenadas por ID.
func (s *Server) Sessions() []*Session {
	s.mu.Lock()
	out := make([]*Session, 0, len(s.sessions))
	for _, x := range s.sessions {
		out = append(out, x)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) reject(conn net.Conn, reason string) {
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_ = WriteMessage(conn, &psychoscopev1.MensagemIPC{
		IdMensagem: NewID(), Timestamp: timestamppb.Now(),
		Payload: &psychoscopev1.MensagemIPC_HelloResposta{HelloResposta: &psychoscopev1.HelloResposta{
			Aceito: false, MensagemErro: reason, VersaoCore: s.cfg.CoreVersion,
		}},
	})
}

// handshake valida credenciais e Hello e registra a sessao. Em caso de erro a
// conexao ja foi respondida/descartada; o chamador so precisa fecha-la.
func (s *Server) handshake(conn *net.UnixConn) (*Session, error) {
	cred, err := PeerCredOf(conn)
	if err != nil {
		return nil, fmt.Errorf("credenciais do peer: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HelloTimeout))
	m, err := ReadMessage(conn, 0)
	if err != nil {
		return nil, fmt.Errorf("lendo Hello (pid=%d uid=%d): %w", cred.PID, cred.UID, err)
	}
	h := m.GetHello()
	if h == nil {
		return nil, fmt.Errorf("primeira mensagem nao e Hello (pid=%d uid=%d)", cred.PID, cred.UID)
	}

	deny := func(public string, internal error) (*Session, error) {
		s.reject(conn, public)
		return nil, fmt.Errorf("hello rejeitado (modulo=%q pid=%d uid=%d): %w", h.IdModulo, cred.PID, cred.UID, internal)
	}
	switch {
	case !config.ValidModuleID(h.IdModulo):
		return deny("id_modulo invalido", errors.New("id_modulo invalido"))
	case h.VersaoProtocolo != ProtocolVersion:
		return deny(fmt.Sprintf("versao de protocolo nao suportada (core=%d)", ProtocolVersion),
			fmt.Errorf("versao_protocolo=%d", h.VersaoProtocolo))
	case int64(h.Pid) != int64(cred.PID):
		return deny("pid declarado difere do peer", fmt.Errorf("pid declarado=%d real=%d", h.Pid, cred.PID))
	}
	if err := s.cfg.Auth.Authorize(h, cred); err != nil {
		return deny("nao autorizado", err)
	}

	sess := newSession(s, conn, h, cred)
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil, errors.New("servidor encerrando")
	}
	if _, dup := s.sessions[h.IdModulo]; dup {
		s.mu.Unlock()
		return deny("modulo ja conectado", errors.New("sessao duplicada"))
	}
	s.sessions[h.IdModulo] = sess
	s.mu.Unlock()

	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	err = WriteMessage(conn, &psychoscopev1.MensagemIPC{
		IdMensagem: NewID(), Timestamp: timestamppb.Now(),
		Payload: &psychoscopev1.MensagemIPC_HelloResposta{HelloResposta: &psychoscopev1.HelloResposta{
			Aceito: true, VersaoCore: s.cfg.CoreVersion,
			IntervaloStatusSeg: uint32(max(1, int(s.cfg.StatusInterval/time.Second))),
		}},
	})
	if err != nil {
		s.unregister(sess)
		return nil, fmt.Errorf("enviando HelloResposta: %w", err)
	}
	return sess, nil
}

func (s *Server) unregister(sess *Session) {
	s.mu.Lock()
	if s.sessions[sess.ID] == sess {
		delete(s.sessions, sess.ID)
	}
	s.mu.Unlock()
}

func (s *Server) handle(conn *net.UnixConn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	sess, err := s.handshake(conn)
	<-s.hs // libera o slot de handshake
	if err != nil {
		s.log.Warn("handshake falhou", "err", err)
		return
	}

	s.log.Info("modulo conectado", "modulo", sess.ID, "pid", sess.Cred.PID, "uid", sess.Cred.UID, "versao", sess.ModuleVersion)
	s.cfg.Handler.OnConnect(sess)
	rerr := s.readLoop(sess)
	sess.Close(rerr)
	s.unregister(sess)
	s.cfg.Handler.OnDisconnect(sess, rerr)
	s.log.Info("modulo desconectado", "modulo", sess.ID, "err", rerr)
}

type protocolError struct{ msg string }

func (e protocolError) Error() string { return "violacao de protocolo: " + e.msg }

func (s *Server) readLoop(sess *Session) error {
	window := heartbeatMisses * s.cfg.StatusInterval
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(window))
		m, err := ReadMessage(sess.conn, 0)
		if err != nil {
			var ne net.Error
			switch {
			case err == io.EOF:
				return nil
			case errors.Is(err, net.ErrClosed):
				return sess.Err()
			case errors.As(err, &ne) && ne.Timeout():
				return ErrHeartbeatTimeout
			}
			return err
		}
		sess.touch(nil)

		switch p := m.Payload.(type) {
		case *psychoscopev1.MensagemIPC_Telemetria:
			if p.Telemetria.GetIdModulo() != sess.ID {
				return protocolError{fmt.Sprintf("telemetria com id_modulo %q em sessao %q", p.Telemetria.GetIdModulo(), sess.ID)}
			}
			s.cfg.Handler.OnTelemetry(sess, p.Telemetria)
		case *psychoscopev1.MensagemIPC_Status:
			if p.Status.GetIdModulo() != sess.ID {
				return protocolError{fmt.Sprintf("status com id_modulo %q em sessao %q", p.Status.GetIdModulo(), sess.ID)}
			}
			sess.touch(p.Status)
			s.cfg.Handler.OnStatus(sess, p.Status)
		case *psychoscopev1.MensagemIPC_Resposta:
			if !sess.deliver(p.Resposta) {
				s.log.Warn("resposta a comando desconhecido ou expirado", "modulo", sess.ID, "id_comando", p.Resposta.GetIdComandoReferencia())
			}
		default:
			return protocolError{fmt.Sprintf("payload %T nao permitido apos o handshake", p)}
		}
	}
}

// Handlers compoe varios Handler; todos recebem cada evento, na ordem dada.
func Handlers(hs ...Handler) Handler { return multiHandler(hs) }

type multiHandler []Handler

func (m multiHandler) OnConnect(s *Session) {
	for _, h := range m {
		h.OnConnect(s)
	}
}
func (m multiHandler) OnTelemetry(s *Session, ev *psychoscopev1.EventoTelemetria) {
	for _, h := range m {
		h.OnTelemetry(s, ev)
	}
}
func (m multiHandler) OnStatus(s *Session, st *psychoscopev1.StatusModulo) {
	for _, h := range m {
		h.OnStatus(s, st)
	}
}
func (m multiHandler) OnDisconnect(s *Session, err error) {
	for _, h := range m {
		h.OnDisconnect(s, err)
	}
}
