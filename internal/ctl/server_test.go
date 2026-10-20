package ctl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/store"
	"github.com/psychoscope-io/psychoscope-core/internal/supervisor"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func TestClientListCommandAndStream(t *testing.T) {
	be := &fakeBackend{}
	path, bus, _ := start(t, be, me())
	cl := &Client{Path: path, CallTimeout: 2 * time.Second}
	ctx := context.Background()

	ms, err := cl.List(ctx)
	if err != nil || len(ms) != 2 || ms[0].IdModulo != "mod-a" {
		t.Fatalf("List: %v %v", ms, err)
	}
	if err := cl.Command(ctx, "mod-a", psychoscopev1.ComandoControle_PAUSAR, map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	calls := append([]string(nil), be.calls...)
	be.mu.Unlock()
	if len(calls) != 1 || calls[0] != "mod-a:PAUSAR:v" {
		t.Fatalf("backend: %v", calls)
	}
	be.err = errors.New("modulo recusou")
	if err := cl.Command(ctx, "mod-a", psychoscopev1.ComandoControle_PAUSAR, nil); err == nil || err.Error() != "modulo recusou" {
		t.Fatalf("erro esperado propagado: %v", err)
	}

	// historico + ao vivo
	bus.Publish(&psychoscopev1.Alerta{IdAlerta: "antigo"})
	sctx, cancel := context.WithCancel(ctx)
	st, err := cl.StreamAlerts(sctx, true)
	if err != nil {
		t.Fatal(err)
	}
	bus.Publish(&psychoscopev1.Alerta{IdAlerta: "novo"})
	for _, want := range []string{"antigo", "novo"} {
		select {
		case a := <-st.C:
			if a.IdAlerta != want {
				t.Fatalf("esperado %s, obtido %s", want, a.IdAlerta)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout esperando %s", want)
		}
	}
	cancel()
	select {
	case _, ok := <-st.C:
		if ok {
			t.Fatal("canal deveria fechar apos cancelar o contexto")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canal nao fechou")
	}

	// sem historico: so o que vier depois
	st2, err := cl.StreamAlerts(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	select {
	case a := <-st2.C:
		t.Fatalf("nao deveria reenviar historico: %v", a)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestClientErrors(t *testing.T) {
	cl := &Client{Path: filepath.Join(t.TempDir(), "nao-existe.sock"), DialTimeout: 200 * time.Millisecond}
	if _, err := cl.List(context.Background()); err == nil {
		t.Fatal("esperado erro de conexao")
	}
	if _, err := cl.StreamAlerts(context.Background(), false); err == nil {
		t.Fatal("esperado erro de conexao no stream")
	}
	path, _, _ := start(t, &fakeBackend{}, me())
	cl = &Client{Path: path}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cl.List(ctx); err == nil {
		t.Fatal("contexto cancelado deve falhar")
	}
}

func startWith(t *testing.T, mutate func(*Config)) (*Client, *alerts.Bus) {
	t.Helper()
	bus := alerts.NewBus()
	path := filepath.Join(t.TempDir(), "ctl.sock")
	cfg := Config{Path: path, Backend: &fakeBackend{}, Alerts: bus, UIDs: me(), CommandTimeout: time.Second}
	mutate(&cfg)
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
	return &Client{Path: path, CallTimeout: 3 * time.Second}, bus
}

func mkAlert(id, rule string, sev psychoscopev1.Severidade, at time.Time) *psychoscopev1.Alerta {
	return &psychoscopev1.Alerta{IdAlerta: id, Regra: rule, Severidade: sev, Timestamp: timestamppb.New(at),
		IdModuloOrigem: "mod-a", Descricao: "d " + id, Contexto: map[string]string{"k": id}}
}

func TestListAlertsFromPersistentStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := time.Unix(1_700_000_000, 0)
	var as []*psychoscopev1.Alerta
	for i := 0; i < 20; i++ {
		sev := psychoscopev1.Severidade_SEVERIDADE_BAIXA
		if i%2 == 0 {
			sev = psychoscopev1.Severidade_SEVERIDADE_ALTA
		}
		as = append(as, mkAlert(fmt.Sprintf("id%02d", i), "net.scan.syn", sev, base.Add(time.Duration(i)*time.Minute)))
	}
	_ = st.Insert(context.Background(), as)
	cl, _ := startWith(t, func(c *Config) { c.Store = st })
	ctx := context.Background()

	got, total, err := cl.Alerts(ctx, AlertQuery{Limit: 3})
	if err != nil || total != 20 || len(got) != 3 || got[0].IdAlerta != "id19" {
		t.Fatalf("limite/total/ordem: %v total=%d err=%v", got, total, err)
	}
	got, total, _ = cl.Alerts(ctx, AlertQuery{MinSeverity: psychoscopev1.Severidade_SEVERIDADE_ALTA, Since: base.Add(10 * time.Minute)})
	if total != 5 || len(got) != 5 || got[0].IdAlerta != "id18" {
		t.Fatalf("filtros: total=%d %v", total, got)
	}
	if got, total, _ = cl.Alerts(ctx, AlertQuery{Rule: "outra"}); total != 0 || len(got) != 0 {
		t.Fatalf("regra inexistente: %v %d", got, total)
	}
	if a := got; a != nil {
		t.Fatal("lista vazia deve ser nil")
	}
	// limite enorme e reduzido ao maximo do servidor sem erro
	if got, _, err = cl.Alerts(ctx, AlertQuery{Limit: 1 << 30}); err != nil || len(got) != 20 {
		t.Fatalf("limite grande: %d %v", len(got), err)
	}
	full, _, _ := cl.Alerts(ctx, AlertQuery{Limit: 1})
	if full[0].Contexto["k"] != "id19" || full[0].Timestamp == nil || full[0].IdModuloOrigem != "mod-a" {
		t.Fatalf("campos do alerta: %v", full[0])
	}
}

func TestListAlertsFallsBackToMemoryHistory(t *testing.T) {
	cl, bus := startWith(t, func(c *Config) {})
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 6; i++ {
		sev := psychoscopev1.Severidade_SEVERIDADE_MEDIA
		if i >= 4 {
			sev = psychoscopev1.Severidade_SEVERIDADE_CRITICA
		}
		bus.Publish(mkAlert(fmt.Sprintf("m%d", i), "r", sev, base.Add(time.Duration(i)*time.Second)))
	}
	got, total, err := cl.Alerts(context.Background(), AlertQuery{Limit: 2, MinSeverity: psychoscopev1.Severidade_SEVERIDADE_CRITICA})
	if err != nil || total != 2 || len(got) != 2 || got[0].IdAlerta != "m5" || got[1].IdAlerta != "m4" {
		t.Fatalf("memoria: %v total=%d err=%v", got, total, err)
	}
	got, total, _ = cl.Alerts(context.Background(), AlertQuery{Limit: 2})
	if total != 6 || len(got) != 2 || got[0].IdAlerta != "m5" {
		t.Fatalf("total ignora o limite: %d %v", total, got)
	}
}

type failingStore struct{}

func (failingStore) Query(context.Context, store.Filter) ([]*psychoscopev1.Alerta, uint64, error) {
	return nil, 0, errors.New("segredo interno do banco")
}

func TestListAlertsStoreErrorIsGeneric(t *testing.T) {
	cl, _ := startWith(t, func(c *Config) { c.Store = failingStore{} })
	_, _, err := cl.Alerts(context.Background(), AlertQuery{})
	if err == nil || strings.Contains(err.Error(), "segredo") {
		t.Fatalf("erro deve existir sem vazar detalhes internos: %v", err)
	}
}

func TestMetricsRequest(t *testing.T) {
	cl, _ := startWith(t, func(c *Config) {
		c.Metrics = func() []*psychoscopev1.Metrica {
			return []*psychoscopev1.Metrica{{Nome: "x_total", Tipo: psychoscopev1.TipoMetrica_TIPO_METRICA_CONTADOR, Valor: 3,
				Rotulos: map[string]string{"module": "m"}}}
		}
	})
	ms, err := cl.Metrics(context.Background())
	if err != nil || len(ms) != 1 || ms[0].Nome != "x_total" || ms[0].Valor != 3 || ms[0].Rotulos["module"] != "m" {
		t.Fatalf("metricas: %v %v", ms, err)
	}
	cl2, _ := startWith(t, func(c *Config) {})
	if ms, err := cl2.Metrics(context.Background()); err != nil || len(ms) != 0 {
		t.Fatalf("sem coletor, lista vazia: %v %v", ms, err)
	}
}
