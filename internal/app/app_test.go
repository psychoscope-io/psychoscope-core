package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Bandeira27/psychoscope-core/internal/config"
	"github.com/Bandeira27/psychoscope-core/internal/ctl"
	"github.com/Bandeira27/psychoscope-core/internal/testmod"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
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
		SocketMode: 0o660, StatusInterval: time.Second, CommandTimeout: 2 * time.Second, LogLevel: "debug",
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
		SocketMode: 0o660, StatusInterval: time.Second, CommandTimeout: time.Second, LogLevel: "info",
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
