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

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// ProtocolVersion e a versao do protocolo IPC aceita no Hello.
const ProtocolVersion = 1

// heartbeatMisses: quantos intervalos de status sem nenhuma mensagem tolerar.
const heartbeatMisses = 3

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
				return nil //nolint:nilerr // encerramento pedido: nao e falha
			}
			return err
		}
		select {
		case s.hs <- struct{}{}:
		default:
			s.log.Warn("handshakes simultaneos demais; conexao recusada")
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			<-s.hs
			_ = conn.Close()
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
		_ = conn.Close()
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
			case errors.Is(err, io.EOF):
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
