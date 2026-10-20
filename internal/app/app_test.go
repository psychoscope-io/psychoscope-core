package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/testmod"
	"github.com/psychoscope-io/psychoscope-core/internal/version"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func TestHelperProcess(t *testing.T) {
	if !testmod.Enabled() {
		return
	}
	testmod.Main()
}

func listModules(t *testing.T, c net.Conn) []*psychoscopev1.ModuloInfo {
	t.Helper()
	if err := ctl.WriteRequest(c, &psychoscopev1.RequisicaoControle{IdRequisicao: "l",
		Pedido: &psychoscopev1.RequisicaoControle_ListarModulos{ListarModulos: &psychoscopev1.PedidoListarModulos{}}}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	r, err := ctl.ReadResponse(c)
	if err != nil || !r.Sucesso {
		t.Fatalf("list: %v %v", r, err)
	}
	return r.GetModulos().GetModulos()
}

func command(t *testing.T, c net.Conn, mod string, a psychoscopev1.ComandoControle_TipoAcao) *psychoscopev1.RespostaControle {
	t.Helper()
	if err := ctl.WriteRequest(c, &psychoscopev1.RequisicaoControle{IdRequisicao: "c",
		Pedido: &psychoscopev1.RequisicaoControle_EnviarComando{EnviarComando: &psychoscopev1.PedidoEnviarComando{IdModulo: mod, Acao: a}}}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	r, err := ctl.ReadResponse(c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func waitState(t *testing.T, c net.Conn, want psychoscopev1.EstadoModulo) *psychoscopev1.ModuloInfo {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		if ms := listModules(t, c); len(ms) == 1 && ms[0].Estado == want {
			return ms[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout esperando estado %v", want)
	return nil
}

// Fluxo completo: CLI -> ctl.sock -> supervisor -> core.sock -> modulo (processo real) e de volta.
func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		SocketPath: filepath.Join(dir, "run", "core.sock"), CtlSocketPath: filepath.Join(dir, "run", "ctl.sock"),
		SocketMode: 0o660, StatusInterval: time.Second, CommandTimeout: 2 * time.Second, LogLevel: "debug", Detection: config.DefaultDetection(),
		Modules: []config.ModuleSpec{{
			ID: "mod-net-sensor", Path: os.Args[0], Args: []string{"-test.run=^TestHelperProcess$"}, Env: []string{"PSY_HELPER=1"},
			MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, StableAfter: time.Minute,
			ConnectTimeout: 5 * time.Second, StopGrace: 3 * time.Second,
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	defer cancel()

	var c net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if c, err = net.Dial("unix", cfg.CtlSocketPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("ctl.sock indisponivel: %v", err)
	}
	defer c.Close()

	// Permissoes dos sockets (0660) e do diretorio (0750).
	for _, p := range []string{cfg.SocketPath, cfg.CtlSocketPath} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o660 {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}

	m := waitState(t, c, psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	if m.Pid == 0 || m.UltimoContato == nil {
		t.Fatalf("modulo conectado sem pid/contato: %v", m)
	}
	pid := int(m.Pid)

	if r := command(t, c, "mod-net-sensor", psychoscopev1.ComandoControle_PAUSAR); !r.Sucesso {
		t.Fatalf("PAUSAR: %v", r)
	}
	waitState(t, c, psychoscopev1.EstadoModulo_ESTADO_PAUSADO)
	if r := command(t, c, "mod-net-sensor", psychoscopev1.ComandoControle_RETOMAR); !r.Sucesso {
		t.Fatalf("RETOMAR: %v", r)
	}
	waitState(t, c, psychoscopev1.EstadoModulo_ESTADO_CONECTADO)

	if r := command(t, c, "nao-existe", psychoscopev1.ComandoControle_PAUSAR); r.Sucesso || r.MensagemErro == "" {
		t.Fatalf("modulo desconhecido deveria falhar: %v", r)
	}

	if r := command(t, c, "mod-net-sensor", psychoscopev1.ComandoControle_ENCERRAR); !r.Sucesso {
		t.Fatalf("ENCERRAR: %v", r)
	}
	waitState(t, c, psychoscopev1.EstadoModulo_ESTADO_ENCERRADO)
	if syscall.Kill(pid, 0) != syscall.ESRCH {
		t.Fatal("processo do modulo deveria ter terminado")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run nao terminou apos cancelamento")
	}
	for _, p := range []string{cfg.SocketPath, cfg.CtlSocketPath} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("socket %s deveria ser removido no shutdown (%v)", p, err)
		}
	}
}

func TestSecondInstanceRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		SocketPath: filepath.Join(dir, "core.sock"), CtlSocketPath: filepath.Join(dir, "ctl.sock"),
		SocketMode: 0o660, StatusInterval: time.Second, CommandTimeout: time.Second, LogLevel: "info", Detection: config.DefaultDetection(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", cfg.CtlSocketPath); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := Run(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("segunda instancia deveria falhar")
	}
	cancel()
	<-done
}

// Telemetria real de um processo-modulo -> motor de deteccao -> alerta no ctl.sock.
func TestDetectionAlertReachesControlChannel(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		SocketPath: filepath.Join(dir, "core.sock"), CtlSocketPath: filepath.Join(dir, "ctl.sock"),
		SocketMode: 0o660, StatusInterval: time.Second, CommandTimeout: 2 * time.Second, LogLevel: "info",
		Detection: config.DefaultDetection(),
		Modules: []config.ModuleSpec{{
			ID: "mod-net-sensor", Path: os.Args[0], Args: []string{"-test.run=^TestHelperProcess$"}, Env: []string{"PSY_HELPER=1", "PSY_SCAN=1"},
			MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, StableAfter: time.Minute,
			ConnectTimeout: 5 * time.Second, StopGrace: 3 * time.Second,
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	defer func() {
		cancel()
		<-done
	}()

	cl := &ctl.Client{Path: cfg.CtlSocketPath}
	var stream *ctl.AlertStream
	var err error
	for i := 0; i < 100; i++ {
		// history=true: o alerta pode ter sido gerado antes da assinatura
		if stream, err = cl.StreamAlerts(context.Background(), true); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	select {
	case a := <-stream.C:
		if a.Regra != "net.scan.syn" || a.Contexto["origem"] != "10.0.0.66" || a.Contexto["destino"] != "10.0.0.2" ||
			a.IdModuloOrigem != "mod-net-sensor" || a.IdAlerta == "" || a.Timestamp == nil {
			t.Fatalf("alerta inesperado: %v", a)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("nenhum alerta chegou ao canal de controle")
	}
}

func scanCfg(dir string) *config.Config {
	return &config.Config{
		SocketPath: filepath.Join(dir, "core.sock"), CtlSocketPath: filepath.Join(dir, "ctl.sock"),
		SocketMode: 0o660, StatusInterval: time.Second, CommandTimeout: 2 * time.Second, LogLevel: "info",
		Detection: config.DefaultDetection(),
		Modules: []config.ModuleSpec{{
			ID: "mod-net-sensor", Path: os.Args[0], Args: []string{"-test.run=^TestHelperProcess$"}, Env: []string{"PSY_HELPER=1", "PSY_SCAN=1"},
			MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond, StableAfter: time.Minute,
			ConnectTimeout: 5 * time.Second, StopGrace: 3 * time.Second,
		}},
	}
}

func startDaemon(t *testing.T, cfg *config.Config) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Error("Run nao terminou")
			}
		})
	}
	t.Cleanup(stop)
	// espera o ctl.sock
	for i := 0; i < 200; i++ {
		if c, err := net.Dial("unix", cfg.CtlSocketPath); err == nil {
			c.Close()
			return stop
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("ctl.sock indisponivel")
	return stop
}

func waitAlerts(t *testing.T, cl *ctl.Client, want int) []*psychoscopev1.Alerta {
	t.Helper()
	var got []*psychoscopev1.Alerta
	for i := 0; i < 300; i++ {
		var err error
		if got, _, err = cl.Alerts(context.Background(), ctl.AlertQuery{}); err == nil && len(got) >= want {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("esperava %d alertas, obtive %d", want, len(got))
	return nil
}

// Os alertas sobrevivem a um reinicio do Core: voltam do SQLite, tanto na consulta
// quanto no historico entregue a quem assina o stream.
func TestAlertsSurviveRestartViaSQLite(t *testing.T) {
	dir := t.TempDir()
	cfg := scanCfg(dir)
	cfg.Storage = config.Storage{Enabled: true, Path: filepath.Join(dir, "state", "alerts.db"), RetentionDays: 30, MaxAlerts: 1000}
	cl := &ctl.Client{Path: cfg.CtlSocketPath}

	stop := startDaemon(t, cfg)
	first := waitAlerts(t, cl, 1)
	if first[0].Regra != "net.scan.syn" {
		t.Fatalf("alerta: %v", first[0])
	}
	stop() // encerramento ordenado: o gravador faz a ultima gravacao

	// Segunda vida: sem modulos, para que nenhum alerta novo mascare o historico.
	cfg2 := scanCfg(dir)
	cfg2.Modules = nil
	cfg2.Storage = cfg.Storage
	startDaemon(t, cfg2)
	again := waitAlerts(t, cl, 1)
	if again[0].IdAlerta != first[0].IdAlerta || again[0].Contexto["origem"] != "10.0.0.66" || !again[0].Timestamp.AsTime().Equal(first[0].Timestamp.AsTime()) {
		t.Fatalf("alerta apos reinicio difere:\n%v\n%v", first[0], again[0])
	}
	st, err := cl.StreamAlerts(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	select {
	case a := <-st.C:
		if a.IdAlerta != first[0].IdAlerta {
			t.Fatalf("historico do stream: %v", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("o historico em memoria deveria ter sido repovoado a partir do banco")
	}
	if fi, err := os.Stat(cfg.Storage.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("banco deve ser 0600: %v %v", fi, err)
	}
}

func TestMetricsEndpointAndControlChannel(t *testing.T) {
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := scanCfg(dir)
	cfg.Metrics = config.Metrics{Listen: addr}
	cfg.Storage = config.Storage{Enabled: true, Path: filepath.Join(dir, "a.db")}
	cl := &ctl.Client{Path: cfg.CtlSocketPath}
	startDaemon(t, cfg)
	waitAlerts(t, cl, 1)

	var body string
	for i := 0; i < 100; i++ {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			if strings.Contains(body, `psychoscope_module_up{module="mod-net-sensor"} 1`) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, want := range []string{
		"# TYPE psychoscope_engine_events_processed_total counter",
		"psychoscope_engine_events_processed_total 30",
		"psychoscope_engine_alerts_total 1",
		`psychoscope_module_up{module="mod-net-sensor"} 1`,
		`psychoscope_info{version="` + version.Version + `"} 1`,
		"psychoscope_store_alerts 1",
		"psychoscope_uptime_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrica ausente %q em:\n%s", want, body)
		}
	}

	// o mesmo conjunto chega pelo ctl.sock
	ms, err := cl.Metrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]float64{}
	for _, m := range ms {
		found[m.Nome] = m.Valor
	}
	if found["psychoscope_engine_alerts_total"] != 1 || found["psychoscope_engine_events_processed_total"] != 30 {
		t.Fatalf("metricas via ctl: %v", found)
	}
}

func TestStorageErrorStopsStartupClearly(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "arquivo")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	cfg := scanCfg(dir)
	cfg.Storage = config.Storage{Enabled: true, Path: filepath.Join(blocker, "alerts.db")} // pai e um arquivo
	err := Run(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "storage.enabled=false") {
		t.Fatalf("esperado erro orientando a desligar a persistencia: %v", err)
	}
}

func TestMetricsBindFailureIsReported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	cfg := scanCfg(t.TempDir())
	cfg.Modules = nil
	cfg.Metrics = config.Metrics{Listen: ln.Addr().String()} // porta ocupada
	err = Run(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "metricas") {
		t.Fatalf("erro de bind deve ser reportado: %v", err)
	}
	if _, err := os.Lstat(cfg.CtlSocketPath); !os.IsNotExist(err) {
		t.Errorf("sockets devem ser removidos quando a partida falha: %v", err)
	}
}
