package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/store"
	"github.com/psychoscope-io/psychoscope-core/internal/supervisor"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeBackend struct{ cmds []string }

func (f *fakeBackend) List() []supervisor.Info {
	return []supervisor.Info{{ID: "mod-a", State: psychoscopev1.EstadoModulo_ESTADO_CONECTADO, PID: 7,
		LastStatus: &psychoscopev1.StatusModulo{EventosProcessados: 9, PacotesCapturados: 12, PacotesDescartados: 1}}}
}

func (f *fakeBackend) Command(_ context.Context, id string, a psychoscopev1.ComandoControle_TipoAcao, p map[string]string) error {
	f.cmds = append(f.cmds, fmt.Sprintf("%s:%s:%v", id, a, p))
	return nil
}

func setup(t *testing.T) (*ctl.Client, *alerts.Bus, *store.Store, *fakeBackend) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := alerts.NewBus()
	be := &fakeBackend{}
	srv, err := ctl.NewServer(ctl.Config{
		Path: filepath.Join(dir, "ctl.sock"), Backend: be, Alerts: bus, Store: st,
		UIDs: ipc.NewUIDPolicy(uint32(os.Geteuid()), nil),
		Metrics: func() []*psychoscopev1.Metrica {
			return []*psychoscopev1.Metrica{
				{Nome: "psychoscope_module_up", Valor: 1, Rotulos: map[string]string{"module": "mod-a"}},
				{Nome: "psychoscope_engine_alerts_total", Valor: 3},
			}
		},
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
	return &ctl.Client{Path: filepath.Join(dir, "ctl.sock")}, bus, st, be
}

func al(id, rule string, sev psychoscopev1.Severidade, ago time.Duration) *psychoscopev1.Alerta {
	return &psychoscopev1.Alerta{IdAlerta: id, Regra: rule, Severidade: sev, Descricao: "descricao " + id,
		IdModuloOrigem: "mod-a", Timestamp: timestamppb.New(time.Now().Add(-ago))}
}

func runCLI(t *testing.T, cl *ctl.Client, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := run(ctx, cl, args, &out)
	return out.String(), err
}

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "90s": 90 * time.Second, "15m": 15 * time.Minute, "2h": 2 * time.Hour, "7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour} {
		if got, err := parseSince(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"-5m", "0s", "abc", "d", "0d", "-1d", "5x"} {
		if _, err := parseSince(bad); err == nil {
			t.Errorf("%q deveria falhar", bad)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]psychoscopev1.Severidade{
		"": psychoscopev1.Severidade_SEVERIDADE_DESCONHECIDA, "baixa": psychoscopev1.Severidade_SEVERIDADE_BAIXA,
		"MEDIA": psychoscopev1.Severidade_SEVERIDADE_MEDIA, "média": psychoscopev1.Severidade_SEVERIDADE_MEDIA,
		"Alta": psychoscopev1.Severidade_SEVERIDADE_ALTA, "crítica": psychoscopev1.Severidade_SEVERIDADE_CRITICA,
	} {
		if got, err := parseSeverity(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := parseSeverity("grave"); err == nil {
		t.Error("severidade invalida deveria falhar")
	}
}

func TestListAndCmd(t *testing.T) {
	cl, _, _, be := setup(t)
	out, err := runCLI(t, cl, "list")
	if err != nil || !strings.Contains(out, "mod-a") || !strings.Contains(out, "CONECTADO") || !strings.Contains(out, "12") {
		t.Fatalf("list: %q %v", out, err)
	}
	out, err = runCLI(t, cl, "cmd", "mod-a", "reconfigure", "bpf=udp")
	if err != nil || strings.TrimSpace(out) != "ok" || len(be.cmds) != 1 || be.cmds[0] != "mod-a:RECONFIGURAR:map[bpf:udp]" {
		t.Fatalf("cmd: %q %v %v", out, err, be.cmds)
	}
	for _, bad := range [][]string{{"cmd"}, {"cmd", "mod-a"}, {"cmd", "mod-a", "explodir"}, {"cmd", "mod-a", "pause", "semigual"}, {"nada"}} {
		if _, err := runCLI(t, cl, bad...); err == nil {
			t.Errorf("%v deveria falhar", bad)
		}
	}
}

func TestAlertsHistoryQuery(t *testing.T) {
	cl, _, st, _ := setup(t)
	_ = st.Insert(context.Background(), []*psychoscopev1.Alerta{
		al("a1", "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_MEDIA, 3*time.Hour),
		al("a2", "net.dns.tunnel", psychoscopev1.Severidade_SEVERIDADE_ALTA, 2*time.Hour),
		al("a3", "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_ALTA, 10*time.Minute),
		al("a4", "net.dns.tunnel", psychoscopev1.Severidade_SEVERIDADE_CRITICA, time.Minute),
	})
	out, err := runCLI(t, cl, "alerts", "--history")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 5 || !strings.Contains(lines[0], "descricao a1") || !strings.Contains(lines[3], "descricao a4") || lines[4] != "-- 4 de 4 alertas --" {
		t.Fatalf("historico cronologico (mais novo por ultimo):\n%s", out)
	}
	out, _ = runCLI(t, cl, "alerts", "--history", "--min-severity", "alta", "--since", "1h")
	if strings.Contains(out, "a1") || strings.Contains(out, "a2") || !strings.Contains(out, "a3") || !strings.Contains(out, "-- 2 de 2 alertas --") {
		t.Fatalf("filtros severidade+janela:\n%s", out)
	}
	out, _ = runCLI(t, cl, "alerts", "--history", "--rule", "net.dns.tunnel", "-n", "1")
	if !strings.Contains(out, "descricao a4") || strings.Contains(out, "descricao a2") || !strings.Contains(out, "-- 1 de 2 alertas --") {
		t.Fatalf("regra + limite (total ignora limite):\n%s", out)
	}
	out, _ = runCLI(t, cl, "alerts", "--history", "--module", "outro")
	if !strings.Contains(out, "-- 0 de 0 alertas --") {
		t.Fatalf("modulo inexistente:\n%s", out)
	}
	for _, bad := range [][]string{
		{"alerts", "--rule", "x"}, // filtros sem --history
		{"alerts", "--history", "--since", "ontem"},
		{"alerts", "--history", "--min-severity", "grave"},
		{"alerts", "--history", "extra"},
		{"alerts", "--bogus"},
	} {
		if _, err := runCLI(t, cl, bad...); err == nil {
			t.Errorf("%v deveria falhar", bad)
		}
	}
}

func TestAlertsLiveStream(t *testing.T) {
	cl, bus, _, _ := setup(t)
	bus.Publish(al("antigo", "r", psychoscopev1.Severidade_SEVERIDADE_BAIXA, time.Hour))

	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cl, []string{"alerts"}, &out) }()
	time.Sleep(300 * time.Millisecond)
	bus.Publish(al("novo", "r", psychoscopev1.Severidade_SEVERIDADE_ALTA, 0))
	time.Sleep(300 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "descricao antigo") || !strings.Contains(s, "descricao novo") {
		t.Fatalf("stream com historico:\n%s", s)
	}

	out.Reset()
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { done <- run(ctx2, cl, []string{"alerts", "--no-history"}, &out) }()
	time.Sleep(300 * time.Millisecond)
	cancel2()
	<-done
	if strings.Contains(out.String(), "antigo") {
		t.Fatalf("--no-history nao deve reenviar historico: %q", out.String())
	}
}

func TestMetricsCommand(t *testing.T) {
	cl, _, _, _ := setup(t)
	out, err := runCLI(t, cl, "metrics")
	if err != nil || !strings.Contains(out, "psychoscope_module_up{module=mod-a}") || !strings.Contains(out, "psychoscope_engine_alerts_total") {
		t.Fatalf("metrics: %q %v", out, err)
	}
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 2 || !strings.HasPrefix(lines[0], "psychoscope_engine_alerts_total") {
		t.Fatalf("ordenado por nome:\n%s", out)
	}
}

func TestTUIRequiresTerminal(t *testing.T) {
	cl, _, _, _ := setup(t)
	if _, err := runCLI(t, cl); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("sem tty deve explicar: %v", err)
	}
}
