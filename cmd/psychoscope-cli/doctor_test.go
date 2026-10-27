package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/supervisor"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var doctorNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// fakeEnv troca o que o doctor le do sistema.
type fakeEnv struct {
	info      sockInfo
	infoErr   error
	state     string
	hasSystem bool
	specs     []config.ModuleSpec
	specsErr  error
	checkOut  string
	checkErr  error
	checked   []string
}

func (f *fakeEnv) SocketInfo(string) (sockInfo, error)                 { return f.info, f.infoErr }
func (f *fakeEnv) ServiceState(context.Context, string) (string, bool) { return f.state, f.hasSystem }
func (f *fakeEnv) Modules(string) ([]config.ModuleSpec, error)         { return f.specs, f.specsErr }
func (f *fakeEnv) SensorCheck(_ context.Context, bin string, a []string) (string, error) {
	f.checked = append(f.checked, bin+" "+strings.Join(a, " "))
	return f.checkOut, f.checkErr
}

func healthy(id string) supervisor.Info {
	return supervisor.Info{ID: id, State: psychoscopev1.EstadoModulo_ESTADO_CONECTADO, PID: 7,
		ModuleVersion: "0.3.0", ConnectedSince: doctorNow.Add(-90 * time.Minute), LastContact: doctorNow,
		LastStatus: &psychoscopev1.StatusModulo{PacotesCapturados: 100_000}}
}

type listBackend struct{ infos []supervisor.Info }

func (l *listBackend) List() []supervisor.Info { return l.infos }
func (l *listBackend) Command(context.Context, string, psychoscopev1.ComandoControle_TipoAcao, map[string]string) error {
	return nil
}

// doctorServer sobe um servidor de controle real com os modulos dados.
func doctorServer(t *testing.T, infos []supervisor.Info, uids ipc.UIDPolicy) *ctl.Client {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ctl.sock")
	srv, err := ctl.NewServer(ctl.Config{
		Path: path, Backend: &listBackend{infos}, Alerts: alerts.NewBus(), UIDs: uids,
		Metrics: func() []*psychoscopev1.Metrica {
			return []*psychoscopev1.Metrica{
				{Nome: "psychoscope_info", Valor: 1, Rotulos: map[string]string{"version": "0.7.0"}},
				{Nome: "psychoscope_uptime_seconds", Valor: 3700},
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
	return &ctl.Client{Path: path, CallTimeout: 5 * time.Second}
}

func runDoctor(t *testing.T, cl *ctl.Client, env doctorEnv, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := doctorRun{cl: cl, env: env, now: func() time.Time { return doctorNow }}.run(ctx, args, &out)
	return out.String(), err
}

func TestDoctorHealthyInstallation(t *testing.T) {
	cl := doctorServer(t, []supervisor.Info{healthy("mod-net-sensor")}, ipc.NewUIDPolicy(uint32(os.Geteuid()), nil))
	out, err := runDoctor(t, cl, &fakeEnv{state: "active", hasSystem: true})
	if err != nil {
		t.Fatalf("instalacao saudavel nao deve falhar: %v\n%s", err, out)
	}
	for _, want := range []string{"[ok]", "servico systemd: psychoscope ativo", "versao 0.7.0, ligado ha 1h 1m",
		"conectado ha 1h 30m, versao 0.3.0, pid 7", "nenhuma (100000 pacotes capturados)", "resultado: 0 falha(s), 0 aviso(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("saida sem %q:\n%s", want, out)
		}
	}
}

func TestDoctorReportsLossAndExitsNonZero(t *testing.T) {
	m := healthy("mod-net-sensor")
	m.LastStatus = &psychoscopev1.StatusModulo{PacotesCapturados: 1000, PacotesDescartados: 50,
		Contadores: map[string]uint64{"perda.kernel": 50}}
	cl := doctorServer(t, []supervisor.Info{m}, ipc.NewUIDPolicy(uint32(os.Geteuid()), nil))
	out, err := runDoctor(t, cl, &fakeEnv{})
	if !errors.Is(err, errDoctorFailed) {
		t.Fatalf("perda de 5%% deve falhar, err=%v\n%s", err, out)
	}
	for _, want := range []string{"[falha]", "50 descartes em 1000 pacotes (5.00%)", "como corrigir: o trafego supera a captura", "resultado: 1 falha(s), 0 aviso(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("saida sem %q:\n%s", want, out)
		}
	}
}

func TestDoctorJSON(t *testing.T) {
	m := healthy("mod-net-sensor")
	m.State = psychoscopev1.EstadoModulo_ESTADO_PAUSADO
	cl := doctorServer(t, []supervisor.Info{m}, ipc.NewUIDPolicy(uint32(os.Geteuid()), nil))
	out, err := runDoctor(t, cl, &fakeEnv{}, "--json")
	if err != nil {
		t.Fatalf("so avisos nao devem falhar: %v", err)
	}
	var got jsonReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("JSON invalido: %v\n%s", err, out)
	}
	if got.Resultado.Falhas != 0 || got.Resultado.Avisos != 1 {
		t.Errorf("resultado = %+v", got.Resultado)
	}
	var paused *jsonFinding
	for i, a := range got.Achados {
		if a.Item == "modulo mod-net-sensor" {
			paused = &got.Achados[i]
		}
	}
	if paused == nil || paused.Nivel != "aviso" || !strings.Contains(paused.ComoCorrigir, "resume") {
		t.Errorf("achado do modulo pausado = %+v", paused)
	}
}

func TestDoctorWithoutSocketSkipsDependentChecks(t *testing.T) {
	cl := &ctl.Client{Path: filepath.Join(t.TempDir(), "ctl.sock")}
	out, err := runDoctor(t, cl, &fakeEnv{infoErr: fs.ErrNotExist, state: "inactive", hasSystem: true})
	if !errors.Is(err, errDoctorFailed) {
		t.Fatalf("socket ausente deve falhar: %v", err)
	}
	for _, want := range []string{"nao existe", "sudo systemctl start psychoscope", "psychoscope esta inactive", "[pulado]", "o Core nao respondeu", "resultado: 2 falha(s), 0 aviso(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("saida sem %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "modulo ") {
		t.Errorf("sem Core nao ha o que dizer dos modulos:\n%s", out)
	}
}

func TestDoctorPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignora permissoes de arquivo")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "run")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	cl := &ctl.Client{Path: filepath.Join(sub, "ctl.sock")}
	if err := os.Chmod(sub, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	out, err := runDoctor(t, cl, &fakeEnv{info: sockInfo{Mode: 0o660, UID: 998, GID: 997}})
	if !errors.Is(err, errDoctorFailed) || !strings.Contains(out, "sem permissao para abrir (modo 0660, dono uid 998, grupo 997)") ||
		!strings.Contains(out, "usermod -aG psychoscope") {
		t.Fatalf("err=%v\n%s", err, out)
	}
}

func TestDoctorUnauthorizedUID(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root e sempre autorizado")
	}
	cl := doctorServer(t, nil, ipc.NewUIDPolicy(uint32(os.Geteuid())+1, nil))
	out, err := runDoctor(t, cl, &fakeEnv{})
	if !errors.Is(err, errDoctorFailed) || !strings.Contains(out, "fechou a conexao sem responder") || !strings.Contains(out, "allowed_uids") {
		t.Fatalf("err=%v\n%s", err, out)
	}
}

func TestCheckSocketClassification(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		xdg     bool
		wantIn  string
		wantFix string
	}{
		{"ausente", fmt.Errorf("dial: %w", fs.ErrNotExist), false, "nao existe", "systemctl start"},
		{"ausente no diretorio do usuario", fs.ErrNotExist, true, "usa /run/psychoscope/ctl.sock", "--ctl-socket /run/psychoscope/ctl.sock"},
		{"recusada", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), false, "ninguem escuta", "systemctl restart"},
		{"fechada", io.EOF, false, "nao esta autorizado", "allowed_uids"},
		{"fechada no meio", io.ErrUnexpectedEOF, false, "nao esta autorizado", "allowed_uids"},
		{"reiniciada pelo Core", fmt.Errorf("read: %w", syscall.ECONNRESET), false, "nao esta autorizado", "allowed_uids"},
		{"outra", errors.New("boom"), false, "boom", "journalctl"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := checkSocket("/x/ctl.sock", c.err, sockInfo{}, errors.New("sem info"), c.xdg)
			if f.Level != levelFail || !strings.Contains(f.Detail, c.wantIn) || !strings.Contains(f.Fix, c.wantFix) {
				t.Errorf("achado = %+v", f)
			}
		})
	}
	if f := checkSocket("/x", nil, sockInfo{}, nil, false); f.Level != levelOK {
		t.Errorf("sem erro deve ser ok: %+v", f)
	}
}

func TestCheckService(t *testing.T) {
	if _, ok := checkService("", false, true); ok {
		t.Error("sem systemctl a verificacao e pulada")
	}
	cases := []struct {
		state string
		core  bool
		want  level
	}{{"active", true, levelOK}, {"inactive", true, levelWarn}, {"inactive", false, levelFail}, {"", false, levelFail}}
	for _, c := range cases {
		if f, _ := checkService(c.state, true, c.core); f.Level != c.want {
			t.Errorf("estado %q, core responde=%v: nivel %v, esperado %v", c.state, c.core, f.Level, c.want)
		}
	}
}

func TestModuleLossThreshold(t *testing.T) {
	mod := func(captured, dropped uint64) *psychoscopev1.ModuloInfo {
		return &psychoscopev1.ModuloInfo{IdModulo: "s", Estado: psychoscopev1.EstadoModulo_ESTADO_CONECTADO,
			UltimoStatus: &psychoscopev1.StatusModulo{PacotesCapturados: captured, PacotesDescartados: dropped,
				Contadores: map[string]uint64{"perda.fila_eventos": dropped}}}
	}
	cases := []struct {
		captured, dropped uint64
		want              level
	}{{1000, 0, levelOK}, {1000, 1, levelWarn}, {1000, 9, levelWarn}, {1000, 10, levelFail}, {1000, 500, levelFail}, {0, 1, levelFail}}
	for _, c := range cases {
		f, ok := moduleLoss(mod(c.captured, c.dropped))
		if !ok || f.Level != c.want {
			t.Errorf("%d/%d: nivel %v (ok=%v), esperado %v", c.dropped, c.captured, f.Level, ok, c.want)
		}
	}
	if _, ok := moduleLoss(&psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_PAUSADO}); ok {
		t.Error("modulo desconectado nao tem perda a avaliar")
	}
	if f, _ := moduleLoss(mod(1000, 5)); !strings.Contains(f.Fix, "Core nao acompanha") {
		t.Errorf("perda na fila de eventos aponta o Core: %q", f.Fix)
	}
}

func TestModuleState(t *testing.T) {
	cases := []struct {
		name string
		m    *psychoscopev1.ModuloInfo
		want level
	}{
		{"conectado", &psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_CONECTADO}, levelOK},
		{"reiniciou", &psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_CONECTADO, Reinicios: 3}, levelWarn},
		{"pausado", &psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_PAUSADO}, levelWarn},
		{"reiniciando", &psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_REINICIANDO}, levelWarn},
		{"falhou", &psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_FALHOU, UltimoErro: "saiu com 1"}, levelFail},
		{"encerrado", &psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_ENCERRADO}, levelFail},
		{"desconhecido", &psychoscopev1.ModuloInfo{}, levelWarn},
	}
	for _, c := range cases {
		if f := moduleState(c.m, doctorNow); f.Level != c.want {
			t.Errorf("%s: nivel %v, esperado %v (%+v)", c.name, f.Level, c.want, f)
		}
	}
	if f := moduleState(&psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_FALHOU, UltimoErro: strings.Repeat("x", 5000)}, doctorNow); len(f.Detail) > 400 {
		t.Errorf("erro do modulo deve ser truncado, detalhe com %d bytes", len(f.Detail))
	}
	if fs := checkModules(nil, doctorNow); len(fs) != 1 || fs[0].Level != levelWarn {
		t.Errorf("sem modulos: %+v", fs)
	}
	conn := &psychoscopev1.ModuloInfo{Estado: psychoscopev1.EstadoModulo_ESTADO_CONECTADO, ConectadoDesde: timestamppb.New(doctorNow.Add(time.Hour))}
	if f := moduleState(conn, doctorNow); !strings.Contains(f.Detail, "ha 0s") {
		t.Errorf("relogio atrasado nao pode gerar tempo negativo: %q", f.Detail)
	}
}

func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{-time.Second: "0s", 45 * time.Second: "45s", 125 * time.Second: "2m 5s",
		125 * time.Minute: "2h 5m", 76 * time.Hour: "3d 4h"} {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, esperado %q", d, got, want)
		}
	}
}

func TestSensorFindings(t *testing.T) {
	out := "[ok]    fonte: wlp2s0\n[falha] captura: sem permissao\ncomo corrigir: sudo setcap cap_net_raw+ep /usr/local/bin/mod-net-sensor\n[aviso] fila: pequena\nresultado: 1 falha(s), 1 aviso(s)\n"
	got := sensorFindings("s", out, errors.New("exit status 1"))
	if len(got) != 2 || got[0].Level != levelFail || got[0].Detail != "captura: sem permissao" || !strings.HasPrefix(got[0].Fix, "sudo setcap") || got[1].Level != levelWarn {
		t.Errorf("achados = %+v", got)
	}
	if got := sensorFindings("s", "[ok]    tudo\n", nil); len(got) != 1 || got[0].Level != levelOK {
		t.Errorf("passou: %+v", got)
	}
	if got := sensorFindings("s", "Segmentation fault", errors.New("signal: segmentation fault")); len(got) != 1 || got[0].Level != levelFail {
		t.Errorf("saida sem formato conhecido e com erro e falha: %+v", got)
	}
	if got := sensorFindings("s", "", context.DeadlineExceeded); len(got) != 1 || !strings.Contains(got[0].Detail, "a tempo") {
		t.Errorf("timeout: %+v", got)
	}
	hostile := strings.Repeat("[falha] "+strings.Repeat("a", 5000)+"\n", 100)
	got = sensorFindings("s", hostile, nil)
	if len(got) != maxSensorFindings || len(got[0].Detail) > maxSensorLine+3 {
		t.Errorf("saida hostil: %d achados, detalhe com %d bytes", len(got), len(got[0].Detail))
	}
}

func TestDoctorSensorFlag(t *testing.T) {
	cl := doctorServer(t, []supervisor.Info{healthy("mod-net-sensor")}, ipc.NewUIDPolicy(uint32(os.Geteuid()), nil))
	env := &fakeEnv{
		specs: []config.ModuleSpec{
			{ID: "mod-net-sensor", Path: "/usr/local/bin/mod-net-sensor", Args: []string{"-i", "wlp2s0"}},
			{ID: "outro", Path: "/usr/local/bin/outro"},
		},
		checkOut: "[falha] captura: sem permissao\ncomo corrigir: sudo setcap ...\n", checkErr: errors.New("exit status 1"),
	}
	out, err := runDoctor(t, cl, env, "--sensor", "--config", "/tmp/x.json")
	if !errors.Is(err, errDoctorFailed) || len(env.checked) != 1 || env.checked[0] != "/usr/local/bin/mod-net-sensor -i wlp2s0" {
		t.Fatalf("so o sensor deve ser checado, err=%v checked=%v\n%s", err, env.checked, out)
	}
	if !strings.Contains(out, "sudo -u psychoscope /usr/local/bin/mod-net-sensor -i wlp2s0 --check") || !strings.Contains(out, "captura: sem permissao") {
		t.Errorf("saida:\n%s", out)
	}
	if out, _ := runDoctor(t, cl, &fakeEnv{}, "--sensor"); strings.Contains(out, "sensor mod-net-sensor") {
		t.Errorf("sem --sensor nada e executado, mas com --sensor e sem modulos deve avisar:\n%s", out)
	}
	env = &fakeEnv{specsErr: errors.New("permission denied")}
	if out, err := runDoctor(t, cl, env, "--sensor"); err != nil || !strings.Contains(out, "configuracao: permission denied") {
		t.Errorf("config ilegivel e so aviso, err=%v\n%s", err, out)
	}
}

func TestDoctorDoesNotRunSensorByDefault(t *testing.T) {
	cl := doctorServer(t, []supervisor.Info{healthy("mod-net-sensor")}, ipc.NewUIDPolicy(uint32(os.Geteuid()), nil))
	env := &fakeEnv{specs: []config.ModuleSpec{{ID: "s", Path: "/bin/mod-net-sensor"}}}
	if _, err := runDoctor(t, cl, env); err != nil || len(env.checked) != 0 {
		t.Fatalf("err=%v, executou %v", err, env.checked)
	}
}

func TestParseDoctorArgs(t *testing.T) {
	if o, err := parseDoctorArgs([]string{"--sensor", "--json", "--config", "/x"}); err != nil || !o.sensor || !o.json || o.config != "/x" {
		t.Errorf("opcoes = %+v, %v", o, err)
	}
	for _, bad := range [][]string{{"--nope"}, {"extra"}, {"--config"}} {
		if _, err := parseDoctorArgs(bad); err == nil || !strings.Contains(err.Error(), "uso: doctor") {
			t.Errorf("%v deve devolver o uso, err=%v", bad, err)
		}
	}
}

func TestReportCountsIgnoreSkipped(t *testing.T) {
	r := report{{Level: levelFail}, {Level: levelWarn}, {Level: levelWarn}, {Level: levelSkip}, {Level: levelOK}}
	if f, w := r.counts(); f != 1 || w != 2 {
		t.Errorf("counts = %d, %d", f, w)
	}
}
