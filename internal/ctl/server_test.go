package ctl

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bandeira27/psychoscope-core/internal/alerts"
	"github.com/Bandeira27/psychoscope-core/internal/ipc"
	"github.com/Bandeira27/psychoscope-core/internal/supervisor"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
)

type fakeBackend struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeBackend) List() []supervisor.Info {
	return []supervisor.Info{
		{ID: "mod-a", State: psychoscopev1.EstadoModulo_ESTADO_CONECTADO, PID: 123, Restarts: 2,
			LastContact: time.Unix(1700000000, 0), LastStatus: &psychoscopev1.StatusModulo{IdModulo: "mod-a", EventosProcessados: 9}},
		{ID: "mod-b", State: psychoscopev1.EstadoModulo_ESTADO_REINICIANDO, LastError: "caiu"},
	}
}

func (f *fakeBackend) Command(_ context.Context, id string, a psychoscopev1.ComandoControle_TipoAcao, p map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id+":"+a.String()+":"+p["k"])
	return f.err
}

func start(t *testing.T, be Backend, uids ipc.UIDPolicy) (path string, bus *alerts.Bus, srv *Server) {
	t.Helper()
	bus = alerts.NewBus()
	path = filepath.Join(t.TempDir(), "ctl.sock")
	srv, err := NewServer(Config{Path: path, Backend: be, Alerts: bus, UIDs: uids, CommandTimeout: time.Second})
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
	return path, bus, srv
}

func me() ipc.UIDPolicy { return ipc.NewUIDPolicy(uint32(os.Geteuid()), nil) }

func rpc(t *testing.T, c net.Conn, req *psychoscopev1.RequisicaoControle) *psychoscopev1.RespostaControle {
	t.Helper()
	if err := WriteRequest(c, req); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	r, err := ReadResponse(c)
	if err != nil {
		t.Fatalf("lendo resposta: %v", err)
	}
	return r
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

func TestListModules(t *testing.T) {
	path, _, _ := start(t, &fakeBackend{}, me())
	c := dial(t, path)
	r := rpc(t, c, &psychoscopev1.RequisicaoControle{IdRequisicao: "r1",
		Pedido: &psychoscopev1.RequisicaoControle_ListarModulos{ListarModulos: &psychoscopev1.PedidoListarModulos{}}})
	if !r.Sucesso || r.IdRequisicaoReferencia != "r1" {
		t.Fatalf("resposta: %v", r)
	}
	ms := r.GetModulos().GetModulos()
	if len(ms) != 2 || ms[0].IdModulo != "mod-a" || ms[0].Pid != 123 || ms[0].Reinicios != 2 ||
		ms[0].Estado != psychoscopev1.EstadoModulo_ESTADO_CONECTADO || ms[0].UltimoContato.GetSeconds() != 1700000000 ||
		ms[0].UltimoStatus.EventosProcessados != 9 {
		t.Fatalf("modulos: %v", ms)
	}
	if ms[1].UltimoContato != nil || ms[1].UltimoErro != "caiu" || ms[1].Pid != 0 {
		t.Fatalf("mod-b: %v", ms[1])
	}
}

func cmdReq(id, mod string, a psychoscopev1.ComandoControle_TipoAcao) *psychoscopev1.RequisicaoControle {
	return &psychoscopev1.RequisicaoControle{IdRequisicao: id,
		Pedido: &psychoscopev1.RequisicaoControle_EnviarComando{EnviarComando: &psychoscopev1.PedidoEnviarComando{
			IdModulo: mod, Acao: a, Parametros: map[string]string{"k": "v"}}}}
}

func TestSendCommand(t *testing.T) {
	be := &fakeBackend{}
	path, _, _ := start(t, be, me())
	c := dial(t, path)

	if r := rpc(t, c, cmdReq("c1", "mod-a", psychoscopev1.ComandoControle_PAUSAR)); !r.Sucesso {
		t.Fatalf("esperado sucesso: %v", r)
	}
	if len(be.calls) != 1 || be.calls[0] != "mod-a:PAUSAR:v" {
		t.Fatalf("backend recebeu %v", be.calls)
	}

	be.err = errors.New("modulo recusou")
	if r := rpc(t, c, cmdReq("c2", "mod-a", psychoscopev1.ComandoControle_RETOMAR)); r.Sucesso || r.MensagemErro != "modulo recusou" {
		t.Fatalf("esperado erro propagado: %v", r)
	}

	n := len(be.calls)
	for _, bad := range []*psychoscopev1.RequisicaoControle{
		cmdReq("c3", "", psychoscopev1.ComandoControle_PAUSAR),
		cmdReq("c4", "mod-a", psychoscopev1.ComandoControle_ACAO_DESCONHECIDA),
	} {
		if r := rpc(t, c, bad); r.Sucesso {
			t.Fatalf("requisicao invalida deveria falhar: %v", r)
		}
	}
	if len(be.calls) != n {
		t.Fatal("backend nao deveria ser chamado para requisicoes invalidas")
	}
}

func TestEmptyRequestIsAnErrorResponse(t *testing.T) {
	path, _, _ := start(t, &fakeBackend{}, me())
	c := dial(t, path)
	if r := rpc(t, c, &psychoscopev1.RequisicaoControle{IdRequisicao: "x"}); r.Sucesso || r.IdRequisicaoReferencia != "x" {
		t.Fatalf("resposta: %v", r)
	}
}

func TestSubscribeAlertsStreamsAndKeepsRPCWorking(t *testing.T) {
	path, bus, _ := start(t, &fakeBackend{}, me())
	c := dial(t, path)
	sub := &psychoscopev1.RequisicaoControle{IdRequisicao: "sub",
		Pedido: &psychoscopev1.RequisicaoControle_AssinarAlertas{AssinarAlertas: &psychoscopev1.PedidoAssinarAlertas{}}}
	if r := rpc(t, c, sub); !r.Sucesso || r.GetAlerta() != nil {
		t.Fatalf("ack da assinatura: %v", r)
	}
	bus.Publish(&psychoscopev1.Alerta{IdAlerta: "a1", Regra: "dns-tunnel", Severidade: psychoscopev1.Severidade_SEVERIDADE_ALTA})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	r, err := ReadResponse(c)
	if err != nil || r.IdRequisicaoReferencia != "sub" || r.GetAlerta().GetIdAlerta() != "a1" {
		t.Fatalf("alerta: %v %v", r, err)
	}

	// Segunda assinatura na mesma conexao e recusada; RPC normal segue funcionando.
	sub2 := &psychoscopev1.RequisicaoControle{IdRequisicao: "sub2", Pedido: sub.Pedido}
	if r := rpc(t, c, sub2); r.Sucesso {
		t.Fatalf("segunda assinatura deveria falhar: %v", r)
	}
	if r := rpc(t, c, &psychoscopev1.RequisicaoControle{IdRequisicao: "l",
		Pedido: &psychoscopev1.RequisicaoControle_ListarModulos{ListarModulos: &psychoscopev1.PedidoListarModulos{}}}); !r.Sucesso {
		t.Fatalf("list apos assinatura: %v", r)
	}
}

func TestSubscriptionReleasedOnDisconnect(t *testing.T) {
	path, bus, _ := start(t, &fakeBackend{}, me())
	c := dial(t, path)
	rpc(t, c, &psychoscopev1.RequisicaoControle{IdRequisicao: "sub",
		Pedido: &psychoscopev1.RequisicaoControle_AssinarAlertas{AssinarAlertas: &psychoscopev1.PedidoAssinarAlertas{}}})
	c.Close()
	// Apos o servidor notar o EOF, publicar nao deve acumular nem travar.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bus.Publish(&psychoscopev1.Alerta{})
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUnauthorizedUIDIsDropped(t *testing.T) {
	path, _, _ := start(t, &fakeBackend{}, ipc.NewUIDPolicy(uint32(os.Geteuid())+4242, nil))
	if os.Geteuid() == 0 {
		t.Skip("root e sempre permitido")
	}
	c := dial(t, path)
	_ = WriteRequest(c, &psychoscopev1.RequisicaoControle{IdRequisicao: "x",
		Pedido: &psychoscopev1.RequisicaoControle_ListarModulos{ListarModulos: &psychoscopev1.PedidoListarModulos{}}})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ReadResponse(c); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("conexao deveria ser fechada sem resposta, obtido %v", err)
	}
}

func TestMalformedFrameClosesConnection(t *testing.T) {
	path, _, _ := start(t, &fakeBackend{}, me())
	for name, raw := range map[string][]byte{
		"oversize":      {0x00, 0x10, 0x00, 0x01},
		"zero":          {0, 0, 0, 0},
		"protobuf ruim": {0, 0, 0, 3, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			c := dial(t, path)
			_, _ = c.Write(raw)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := ReadResponse(c); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("esperado fechamento, obtido %v", err)
			}
		})
	}
}

func TestConnectionLimit(t *testing.T) {
	bus := alerts.NewBus()
	path := filepath.Join(t.TempDir(), "ctl.sock")
	srv, _ := NewServer(Config{Path: path, Backend: &fakeBackend{}, Alerts: bus, UIDs: me(), MaxConns: 1})
	if err := srv.Listen(); err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)
	defer func() { cancel(); srv.Shutdown() }()

	first := dial(t, path)
	time.Sleep(50 * time.Millisecond)
	second := dial(t, path)
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ReadResponse(second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("segunda conexao deveria ser recusada: %v", err)
	}
	_ = first
}

func TestShutdownClosesClients(t *testing.T) {
	path, _, srv := start(t, &fakeBackend{}, me())
	c := dial(t, path)
	time.Sleep(50 * time.Millisecond)
	srv.Shutdown()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ReadResponse(c); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("cliente deveria ser desconectado: %v", err)
	}
}
