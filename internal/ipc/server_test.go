package ipc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type authFunc func(*psychoscopev1.HelloModulo, PeerCred) error

func (f authFunc) Authorize(h *psychoscopev1.HelloModulo, c PeerCred) error { return f(h, c) }

var allowAll = authFunc(func(*psychoscopev1.HelloModulo, PeerCred) error { return nil })

type recHandler struct {
	mu        sync.Mutex
	telemetry []*psychoscopev1.EventoTelemetria
	status    []*psychoscopev1.StatusModulo
	connected chan *Session
	gone      chan error
}

func newRecHandler() *recHandler {
	return &recHandler{connected: make(chan *Session, 8), gone: make(chan error, 8)}
}
func (h *recHandler) OnConnect(s *Session) { h.connected <- s }
func (h *recHandler) OnTelemetry(_ *Session, ev *psychoscopev1.EventoTelemetria) {
	h.mu.Lock()
	h.telemetry = append(h.telemetry, ev)
	h.mu.Unlock()
}
func (h *recHandler) OnStatus(_ *Session, st *psychoscopev1.StatusModulo) {
	h.mu.Lock()
	h.status = append(h.status, st)
	h.mu.Unlock()
}
func (h *recHandler) OnDisconnect(_ *Session, err error) { h.gone <- err }

func startServer(t *testing.T, mutate func(*ServerConfig)) (*Server, *recHandler, string) {
	t.Helper()
	h := newRecHandler()
	cfg := ServerConfig{
		Path:           filepath.Join(t.TempDir(), "core.sock"),
		Mode:           0o660,
		CoreVersion:    "test",
		StatusInterval: time.Second,
		CommandTimeout: 500 * time.Millisecond,
		HelloTimeout:   300 * time.Millisecond,
		Auth:           allowAll,
		Handler:        h,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Skipf("unix sockets indisponiveis: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); srv.Shutdown(); <-done })
	return srv, h, cfg.Path
}

func hello(id string) *psychoscopev1.MensagemIPC {
	return &psychoscopev1.MensagemIPC{
		IdMensagem: "h", Timestamp: timestamppb.Now(),
		Payload: &psychoscopev1.MensagemIPC_Hello{Hello: &psychoscopev1.HelloModulo{
			IdModulo: id, VersaoProtocolo: ProtocolVersion, VersaoModulo: "1.0", Pid: uint32(os.Getpid()),
		}},
	}
}

func dial(t *testing.T, path string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// connect faz o handshake completo e devolve a conexao do "modulo" e a sessao do Core.
func connect(t *testing.T, srv *Server, h *recHandler, path, id string) (net.Conn, *Session) {
	t.Helper()
	c := dial(t, path)
	if err := WriteMessage(c, hello(id)); err != nil {
		t.Fatal(err)
	}
	r := readHello(t, c)
	if !r.Aceito {
		t.Fatalf("hello recusado: %s", r.MensagemErro)
	}
	select {
	case s := <-h.connected:
		return c, s
	case <-time.After(2 * time.Second):
		t.Fatal("OnConnect nao chamado")
	}
	return nil, nil
}

func readHello(t *testing.T, c net.Conn) *psychoscopev1.HelloResposta {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := ReadMessage(c, 0)
	if err != nil {
		t.Fatalf("lendo HelloResposta: %v", err)
	}
	r := m.GetHelloResposta()
	if r == nil {
		t.Fatalf("esperado HelloResposta, obtido %v", m)
	}
	return r
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ReadFrame(c, 0); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("esperado conexao fechada, obtido %v", err)
	}
}

func statusMsg(id string) *psychoscopev1.MensagemIPC {
	return &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Status{Status: &psychoscopev1.StatusModulo{
		IdModulo: id, EventosProcessados: 7, PacotesDescartados: 1,
	}}}
}

func TestHandshakeAccepted(t *testing.T) {
	srv, h, path := startServer(t, func(c *ServerConfig) { c.StatusInterval = 5 * time.Second })
	c := dial(t, path)
	_ = WriteMessage(c, hello("mod-a"))
	r := readHello(t, c)
	if !r.Aceito || r.VersaoCore != "test" || r.IntervaloStatusSeg != 5 {
		t.Fatalf("resposta inesperada: %v", r)
	}
	s := <-h.connected
	if s.ID != "mod-a" || s.Cred.PID != int32(os.Getpid()) || s.Cred.UID != uint32(os.Geteuid()) {
		t.Fatalf("sessao/cred inesperadas: %+v", s)
	}
	if got, ok := srv.Session("mod-a"); !ok || got != s || len(srv.Sessions()) != 1 {
		t.Fatal("sessao nao registrada")
	}
}

func TestHandshakeRejections(t *testing.T) {
	deny := authFunc(func(*psychoscopev1.HelloModulo, PeerCred) error { return errors.New("segredo interno") })
	cases := []struct {
		name   string
		auth   Authorizer
		mutate func(*psychoscopev1.HelloModulo)
		want   string
	}{
		{"pid forjado", allowAll, func(h *psychoscopev1.HelloModulo) { h.Pid++ }, "pid declarado difere do peer"},
		{"versao", allowAll, func(h *psychoscopev1.HelloModulo) { h.VersaoProtocolo = 99 }, "versao de protocolo nao suportada (core=1)"},
		{"id invalido", allowAll, func(h *psychoscopev1.HelloModulo) { h.IdModulo = "../etc" }, "id_modulo invalido"},
		{"id vazio", allowAll, func(h *psychoscopev1.HelloModulo) { h.IdModulo = "" }, "id_modulo invalido"},
		{"nao autorizado", deny, func(*psychoscopev1.HelloModulo) {}, "nao autorizado"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, path := startServer(t, func(c *ServerConfig) { c.Auth = tc.auth })
			c := dial(t, path)
			m := hello("mod-a")
			tc.mutate(m.GetHello())
			_ = WriteMessage(c, m)
			r := readHello(t, c)
			if r.Aceito || r.MensagemErro != tc.want {
				t.Fatalf("esperado recusa %q, obtido %v", tc.want, r)
			}
			expectClosed(t, c)
			if len(srv.Sessions()) != 0 {
				t.Fatal("sessao nao deveria existir")
			}
		})
	}
}

func TestDuplicateModuleRejected(t *testing.T) {
	srv, h, path := startServer(t, nil)
	connect(t, srv, h, path, "mod-a")
	c2 := dial(t, path)
	_ = WriteMessage(c2, hello("mod-a"))
	if r := readHello(t, c2); r.Aceito || r.MensagemErro != "modulo ja conectado" {
		t.Fatalf("duplicata deveria ser recusada: %v", r)
	}
	if len(srv.Sessions()) != 1 {
		t.Fatal("a sessao original deve permanecer")
	}
}

func TestFirstMessageMustBeHello(t *testing.T) {
	_, _, path := startServer(t, nil)
	c := dial(t, path)
	_ = WriteMessage(c, statusMsg("mod-a"))
	expectClosed(t, c)
}

func TestHelloTimeout(t *testing.T) {
	_, _, path := startServer(t, nil)
	c := dial(t, path) // conecta e fica mudo
	expectClosed(t, c)
}

func TestHandshakeLimit(t *testing.T) {
	_, _, path := startServer(t, func(c *ServerConfig) { c.MaxHandshakes = 1; c.HelloTimeout = 700 * time.Millisecond })
	first := dial(t, path) // ocupa o unico slot
	time.Sleep(50 * time.Millisecond)
	second := dial(t, path)
	expectClosed(t, second) // recusada imediatamente, bem antes do HelloTimeout
	_ = first
}

func TestTelemetryAndStatus(t *testing.T) {
	srv, h, path := startServer(t, nil)
	c, s := connect(t, srv, h, path, "mod-a")
	_ = WriteMessage(c, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Telemetria{
		Telemetria: &psychoscopev1.EventoTelemetria{IdModulo: "mod-a"}}})
	_ = WriteMessage(c, statusMsg("mod-a"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		n, m := len(h.telemetry), len(h.status)
		h.mu.Unlock()
		if n == 1 && m == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.telemetry) != 1 || len(h.status) != 1 {
		t.Fatalf("handler recebeu telemetria=%d status=%d", len(h.telemetry), len(h.status))
	}
	if st := s.LastStatus(); st == nil || st.EventosProcessados != 7 {
		t.Fatalf("LastStatus: %v", st)
	}
}

func TestProtocolViolationsCloseSession(t *testing.T) {
	cases := map[string]*psychoscopev1.MensagemIPC{
		"telemetria com id forjado": {Payload: &psychoscopev1.MensagemIPC_Telemetria{Telemetria: &psychoscopev1.EventoTelemetria{IdModulo: "outro"}}},
		"status com id forjado":     statusMsg("outro"),
		"hello repetido":            hello("mod-a"),
		"comando vindo do modulo":   {Payload: &psychoscopev1.MensagemIPC_Comando{Comando: &psychoscopev1.ComandoControle{IdComando: "x"}}},
		"sem payload":               {IdMensagem: "vazio"},
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			srv, h, path := startServer(t, nil)
			c, _ := connect(t, srv, h, path, "mod-a")
			_ = WriteMessage(c, msg)
			select {
			case err := <-h.gone:
				var pe protocolError
				if !errors.As(err, &pe) {
					t.Fatalf("esperado protocolError, obtido %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("sessao nao encerrada")
			}
			expectClosed(t, c)
		})
	}
}

func TestOversizedFrameClosesSession(t *testing.T) {
	srv, h, path := startServer(t, nil)
	c, _ := connect(t, srv, h, path, "mod-a")
	_, _ = c.Write([]byte{0x00, 0x10, 0x00, 0x01})
	if err := <-h.gone; !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("esperado ErrFrameTooLarge, obtido %v", err)
	}
}

// modulo simula o lado do sensor respondendo a comandos.
func answerOne(t *testing.T, c net.Conn, ok bool, msg string) *psychoscopev1.ComandoControle {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := ReadMessage(c, 0)
	if err != nil {
		t.Errorf("lendo comando: %v", err)
		return nil
	}
	cmd := m.GetComando()
	if cmd == nil {
		t.Errorf("esperado comando, obtido %v", m)
		return nil
	}
	_ = WriteMessage(c, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Resposta{
		Resposta: &psychoscopev1.RespostaComando{IdComandoReferencia: cmd.IdComando, Sucesso: ok, MensagemErro: msg}}})
	return cmd
}

func TestCommandAckAndNack(t *testing.T) {
	srv, h, path := startServer(t, nil)
	c, s := connect(t, srv, h, path, "mod-a")

	go answerOne(t, c, true, "")
	resp, err := s.Command(context.Background(), psychoscopev1.ComandoControle_PAUSAR, map[string]string{"k": "v"})
	if err != nil || !resp.Sucesso {
		t.Fatalf("ACK esperado: %v %v", resp, err)
	}

	go answerOne(t, c, false, "interface inexistente")
	resp, err = s.Command(context.Background(), psychoscopev1.ComandoControle_RECONFIGURAR, nil)
	if !errors.Is(err, ErrNack) || resp == nil || resp.MensagemErro != "interface inexistente" {
		t.Fatalf("NACK esperado: %v %v", resp, err)
	}
}

func TestCommandTimeoutThenLateReplyIgnored(t *testing.T) {
	srv, h, path := startServer(t, nil)
	c, s := connect(t, srv, h, path, "mod-a")

	errc := make(chan error, 1)
	go func() {
		_, err := s.Command(context.Background(), psychoscopev1.ComandoControle_RETOMAR, nil)
		errc <- err
	}()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := ReadMessage(c, 0) // recebe o comando e nao responde
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("esperado timeout, obtido %v", err)
	}
	// Resposta tardia nao pode derrubar a sessao.
	_ = WriteMessage(c, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Resposta{
		Resposta: &psychoscopev1.RespostaComando{IdComandoReferencia: m.GetComando().IdComando, Sucesso: true}}})
	_ = WriteMessage(c, statusMsg("mod-a"))
	time.Sleep(100 * time.Millisecond)
	select {
	case <-s.Done():
		t.Fatal("sessao nao deveria ter caido")
	default:
	}
}

func TestPendingCommandFailsWhenSessionDrops(t *testing.T) {
	srv, h, path := startServer(t, func(c *ServerConfig) { c.CommandTimeout = 5 * time.Second })
	c, s := connect(t, srv, h, path, "mod-a")
	errc := make(chan error, 1)
	go func() {
		_, err := s.Command(context.Background(), psychoscopev1.ComandoControle_ENCERRAR, nil)
		errc <- err
	}()
	_, _ = ReadMessage(c, 0)
	c.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("esperado ErrSessionClosed, obtido %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Command nao retornou")
	}
	if _, err := s.Command(context.Background(), psychoscopev1.ComandoControle_PAUSAR, nil); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("comando apos queda: %v", err)
	}
}

func TestHeartbeatTimeout(t *testing.T) {
	srv, h, path := startServer(t, func(c *ServerConfig) { c.StatusInterval = 40 * time.Millisecond })
	connect(t, srv, h, path, "mod-a")
	select {
	case err := <-h.gone:
		if !errors.Is(err, ErrHeartbeatTimeout) {
			t.Fatalf("esperado ErrHeartbeatTimeout, obtido %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sessao silenciosa nao foi derrubada")
	}
	if len(srv.Sessions()) != 0 {
		t.Fatal("sessao deve ser removida")
	}
}

func TestHeartbeatKeepsSessionAlive(t *testing.T) {
	srv, h, path := startServer(t, func(c *ServerConfig) { c.StatusInterval = 60 * time.Millisecond })
	c, s := connect(t, srv, h, path, "mod-a")
	for i := 0; i < 8; i++ {
		_ = WriteMessage(c, statusMsg("mod-a"))
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case <-s.Done():
		t.Fatal("sessao com heartbeat nao deve cair")
	default:
	}
}

func TestCleanDisconnectAndReconnect(t *testing.T) {
	srv, h, path := startServer(t, nil)
	c, _ := connect(t, srv, h, path, "mod-a")
	c.Close()
	if err := <-h.gone; err != nil {
		t.Fatalf("desconexao limpa deve ter err=nil, obtido %v", err)
	}
	connect(t, srv, h, path, "mod-a") // id liberado
}

func TestShutdownClosesSessions(t *testing.T) {
	srv, h, path := startServer(t, nil)
	c, _ := connect(t, srv, h, path, "mod-a")
	srv.Shutdown()
	expectClosed(t, c)
	if len(srv.Sessions()) != 0 {
		t.Fatal("sessoes devem ser limpas")
	}
}

func TestListenUnixPermsAndStale(t *testing.T) {
	log := discard()
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "s.sock")

	ln, err := ListenUnix(path, 0o600, log)
	if err != nil {
		t.Skip(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("modo do socket %v", st.Mode().Perm())
	}
	ds, _ := os.Stat(filepath.Dir(path))
	if ds.Mode().Perm() != 0o750 {
		t.Errorf("modo do diretorio %v", ds.Mode().Perm())
	}
	// instancia viva: recusa
	if _, err := ListenUnix(path, 0o600, log); err == nil {
		t.Error("deveria recusar socket de instancia viva")
	}
	// socket obsoleto: fecha SEM remover o arquivo (SetUnlinkOnClose) e reabre
	ln.SetUnlinkOnClose(false)
	ln.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("socket obsoleto deveria permanecer")
	}
	ln2, err := ListenUnix(path, 0o660, log)
	if err != nil {
		t.Fatalf("deveria substituir socket obsoleto: %v", err)
	}
	ln2.Close()

	// arquivo comum: nunca apagar
	reg := filepath.Join(dir, "regular")
	_ = os.WriteFile(reg, []byte("x"), 0o600)
	if _, err := ListenUnix(reg, 0o600, log); err == nil {
		t.Error("nao deveria sobrescrever arquivo regular")
	}
	if b, _ := os.ReadFile(reg); string(b) != "x" {
		t.Error("arquivo regular foi alterado")
	}
}

func TestUIDPolicy(t *testing.T) {
	p := NewUIDPolicy(1000, []uint32{2000})
	for uid, want := range map[uint32]bool{0: true, 1000: true, 2000: true, 1001: false} {
		if p.Allows(uid) != want {
			t.Errorf("uid %d: want %v", uid, want)
		}
	}
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
