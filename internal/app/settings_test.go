package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func settingsCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg := scanCfg(dir)
	cfg.OverridesPath = filepath.Join(dir, "state", "overrides.json")
	return cfg
}

// startDaemonOpts e o startDaemon com opcoes (aqui, a politica de quem pode escrever).
func startDaemonOpts(t *testing.T, cfg *config.Config, opts options) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), opts) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("run: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Error("run nao terminou")
			}
		})
	}
	t.Cleanup(stop)
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

func moduleIs(cl *ctl.Client, want psychoscopev1.EstadoModulo) bool {
	ms, err := cl.List(context.Background())
	return err == nil && len(ms) == 1 && ms[0].Estado == want
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout esperando: %s", what)
}

// restartModule encerra e religa o modulo de teste, que reenvia os 30 SYNs ao conectar.
func restartModule(t *testing.T, cl *ctl.Client) {
	t.Helper()
	ctx := context.Background()
	if err := cl.Command(ctx, "mod-net-sensor", psychoscopev1.ComandoControle_ENCERRAR, nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "modulo encerrado", func() bool { return moduleIs(cl, psychoscopev1.EstadoModulo_ESTADO_ENCERRADO) })
	if err := cl.Command(ctx, "mod-net-sensor", psychoscopev1.ComandoControle_RETOMAR, nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "modulo conectado", func() bool { return moduleIs(cl, psychoscopev1.EstadoModulo_ESTADO_CONECTADO) })
}

func alertCount(t *testing.T, cl *ctl.Client) int {
	t.Helper()
	as, _, err := cl.Alerts(context.Background(), ctl.AlertQuery{})
	if err != nil {
		t.Fatal(err)
	}
	return len(as)
}

// Ponta a ponta: um limiar alterado pelo canal de controle vale ao vivo no motor, o ajuste
// fica gravado com modo 0600 e restaurar devolve o comportamento anterior.
func TestSettingsChangeDetectionLiveAndPersist(t *testing.T) {
	cfg := settingsCfg(t)
	stop := startDaemonOpts(t, cfg, options{admin: func(uint32) bool { return true }})
	cl := &ctl.Client{Path: cfg.CtlSocketPath, CallTimeout: 10 * time.Second}
	ctx := context.Background()

	waitAlerts(t, cl, 1) // 30 portas > limiar padrao (15): alerta de varredura
	if l, err := cl.Config(ctx); err != nil || l.SomenteLeitura || ctl.FindField(l, "detection.scan.vertical_ports").GetValorAtual() != "15" ||
		l.ArquivoAjustes != cfg.OverridesPath {
		t.Fatalf("leitura inicial: %+v %v", l, err)
	}

	// limiar alto: a mesma varredura (reenviada pelo modulo religado) nao alerta mais
	l, err := cl.ApplyConfig(ctx, map[string]string{"detection.scan.vertical_ports": "1000"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f := ctl.FindField(l, "detection.scan.vertical_ports"); f.ValorAtual != "1000" || f.Origem != psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE || len(l.Avisos) != 0 {
		t.Fatalf("resposta do aplicar: %+v avisos=%v", f, l.Avisos)
	}
	if st, err := os.Stat(cfg.OverridesPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("arquivo de ajustes: %v %v", st, err)
	}
	restartModule(t, cl)
	time.Sleep(500 * time.Millisecond) // os SYNs chegam logo depois do Hello
	if n := alertCount(t, cl); n != 1 {
		t.Fatalf("com o limiar em 1000 a varredura nao pode gerar alerta novo: %d alertas", n)
	}

	// restaurar: o limiar volta ao padrao (15) e a varredura volta a alertar (o cooldown foi
	// reiniciado pela reconfiguracao)
	l, err = cl.ApplyConfig(ctx, nil, []string{"detection.scan.vertical_ports"})
	if err != nil {
		t.Fatal(err)
	}
	if f := ctl.FindField(l, "detection.scan.vertical_ports"); f.ValorAtual != "15" || f.Origem != psychoscopev1.OrigemCampo_ORIGEM_CAMPO_PADRAO {
		t.Fatalf("restaurado: %+v", f)
	}
	if _, err := os.Stat(cfg.OverridesPath); !os.IsNotExist(err) {
		t.Fatalf("sem ajustes o arquivo e removido: %v", err)
	}
	restartModule(t, cl)
	waitAlerts(t, cl, 2)

	// um ajuste sobrevive ao reinicio do Core e passa a valer ja na partida
	if _, err := cl.ApplyConfig(ctx, map[string]string{"detection.scan.vertical_ports": "1000"}, nil); err != nil {
		t.Fatal(err)
	}
	stop()
	startDaemonOpts(t, cfg, options{admin: func(uint32) bool { return true }})
	l, err = cl.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f := ctl.FindField(l, "detection.scan.vertical_ports"); f.ValorAtual != "1000" || f.Origem != psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE {
		t.Fatalf("apos reiniciar o Core: %+v", f)
	}
}

// Sem a politica injetada, so o root escreve: um usuario comum le e e recusado ao escrever.
func TestSettingsWriteIsDeniedToNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("o teste pressupoe um usuario comum")
	}
	cfg := settingsCfg(t)
	startDaemonOpts(t, cfg, options{})
	cl := &ctl.Client{Path: cfg.CtlSocketPath, CallTimeout: 10 * time.Second}
	l, err := cl.Config(context.Background())
	if err != nil || !l.SomenteLeitura {
		t.Fatalf("leitura: %+v %v", l, err)
	}
	if _, err := cl.ApplyConfig(context.Background(), map[string]string{"detection.scan.vertical_ports": "1000"}, nil); err == nil {
		t.Fatal("usuario comum nao pode escrever")
	}
	if _, err := os.Stat(cfg.OverridesPath); !os.IsNotExist(err) {
		t.Fatal("nada gravado")
	}
}

func TestInvalidOverridesFileStopsStartupClearly(t *testing.T) {
	cfg := settingsCfg(t)
	if err := os.MkdirAll(filepath.Dir(cfg.OverridesPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.OverridesPath, []byte(`{"modules":[{"id":"x","path":"/bin/sh"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), options{})
	if err == nil || !containsAll(err.Error(), cfg.OverridesPath, "remova") {
		t.Fatalf("a partida deve falhar citando o arquivo e como corrigir: %v", err)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
