package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/settings"
)

// setupConfig sobe um canal de controle com um gerenciador de ajustes de verdade.
func setupConfig(t *testing.T, admin bool) *ctl.Client {
	t.Helper()
	dir := t.TempDir()
	env := config.Env{Getenv: func(string) string { return "" }, Euid: 0, DirUsable: func(string) bool { return false }}
	base, err := config.Load(nil, env)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := settings.New(base, filepath.Join(dir, "state", "overrides.json"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ctl.NewServer(ctl.Config{
		Path: filepath.Join(dir, "ctl.sock"), Backend: &fakeBackend{}, Alerts: alerts.NewBus(),
		UIDs: ipc.NewUIDPolicy(uint32(os.Geteuid()), nil), Settings: mgr,
		Admin: func(uint32) bool { return admin },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)
	t.Cleanup(func() { cancel(); srv.Shutdown() })
	return &ctl.Client{Path: filepath.Join(dir, "ctl.sock"), CallTimeout: 5 * time.Second}
}

func TestConfigListFiltersAndShowsDescriptions(t *testing.T) {
	cl := setupConfig(t, true)
	out, err := runCLI(t, cl, "config")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CAMPO", "VALOR", "PADRAO", "ORIGEM", "detection.window", "detection.scan.vertical_ports",
		"detection.nxdomain.ignore_suffixes", "in-addr.arpa, ip6.arpa", "storage.max_alerts", "padrão", "ajustes gravados em"} {
		if !strings.Contains(out, want) {
			t.Errorf("listagem sem %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "somente leitura") {
		t.Errorf("admin nao ve o aviso de somente leitura:\n%s", out)
	}

	out, _ = runCLI(t, cl, "config", "detection.beacon")
	if strings.Contains(out, "detection.scan") || !strings.Contains(out, "detection.beacon.ignore_destinations") {
		t.Fatalf("filtro por prefixo:\n%s", out)
	}
	out, _ = runCLI(t, cl, "config", "-v", "detection.beacon.ignore_ports")
	if !strings.Contains(out, "Portas de destino TCP ignoradas.") {
		t.Fatalf("-v mostra a descricao do campo:\n%s", out)
	}
	if _, err := runCLI(t, cl, "config", "nao.existe"); err == nil || !strings.Contains(err.Error(), "nenhum campo") {
		t.Fatalf("prefixo sem campos: %v", err)
	}
	if _, err := runCLI(t, cl, "config", "--bogus"); err == nil {
		t.Fatal("opcao desconhecida deve falhar")
	}
}

func TestConfigSetAndReset(t *testing.T) {
	cl := setupConfig(t, true)
	out, err := runCLI(t, cl, "config", "set",
		"detection.scan.vertical_ports=30", "detection.beacon.ignore_ports=123, 443", "detection.window=2m",
		"detection.beacon.ignore_destinations=149.154.160.0/20,2001:67c:4e8::/48")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"detection.scan.vertical_ports: 15 -> 30", "detection.window: 1m -> 2m",
		"detection.beacon.ignore_ports: (vazia) -> 123, 443", "detection.beacon.ignore_destinations: (vazia) -> 149.154.160.0/20, 2001:67c:4e8::/48"} {
		if !strings.Contains(out, want) {
			t.Errorf("set sem %q:\n%s", want, out)
		}
	}
	list, _ := runCLI(t, cl, "config", "detection.scan.vertical_ports")
	if !strings.Contains(list, "30") || !strings.Contains(list, "ajuste") {
		t.Fatalf("o ajuste aparece na listagem com origem ajuste:\n%s", list)
	}

	out, err = runCLI(t, cl, "config", "reset", "detection.scan.vertical_ports", "detection.beacon.ignore_ports")
	if err != nil || !strings.Contains(out, "detection.scan.vertical_ports: 30 -> 15") {
		t.Fatalf("reset: %q %v", out, err)
	}
	// repetir o mesmo valor nao muda nada
	out, err = runCLI(t, cl, "config", "set", "detection.window=2m")
	if err != nil || !strings.Contains(out, "nada mudou") {
		t.Fatalf("valor igual ao atual: %q %v", out, err)
	}
}

func TestConfigSetErrors(t *testing.T) {
	cl := setupConfig(t, true)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"sem argumentos":           {[]string{"config", "set"}, "uso:"},
		"sem igual":                {[]string{"config", "set", "detection.window"}, "campo=valor"},
		"campo desconhecido":       {[]string{"config", "set", "detection.bogus=1"}, "desconhecido ou nao editavel"},
		"nao editavel":             {[]string{"config", "set", "detection.queue_size=1"}, "desconhecido ou nao editavel"},
		"tipo errado (no cliente)": {[]string{"config", "set", "detection.scan.vertical_ports=muitas"}, "numero inteiro"},
		"duracao invalida":         {[]string{"config", "set", "detection.window=dez"}, "duracao"},
		"validacao do Core":        {[]string{"config", "set", "detection.scan.window=5m"}, "detection.window"},
		"valor negativo":           {[]string{"config", "set", "detection.scan.vertical_ports=-1"}, "positivo"},
		"reset sem argumentos":     {[]string{"config", "reset"}, "uso:"},
		"reset desconhecido":       {[]string{"config", "reset", "storage.path"}, "desconhecido ou nao editavel"},
	} {
		if _, err := runCLI(t, cl, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: erro %v, esperado conter %q", name, err, tc.want)
		}
	}
	// nada do que falhou foi aplicado
	if out, _ := runCLI(t, cl, "config", "detection.scan.window"); !strings.Contains(out, "10s") {
		t.Fatalf("a configuracao nao mudou:\n%s", out)
	}
}

func TestConfigWriteIsDeniedWithoutRoot(t *testing.T) {
	cl := setupConfig(t, false)
	out, err := runCLI(t, cl, "config", "detection.scan.vertical_ports")
	if err != nil || !strings.Contains(out, "somente leitura") {
		t.Fatalf("leitura permitida, com aviso: %q %v", out, err)
	}
	if _, err := runCLI(t, cl, "config", "set", "detection.scan.vertical_ports=30"); err == nil || !strings.Contains(err.Error(), "somente o root") {
		t.Fatalf("escrita recusada: %v", err)
	}
}
