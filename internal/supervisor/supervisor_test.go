package supervisor

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/testmod"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func TestMain(m *testing.M) {
	watchdogTick, termGrace = 20*time.Millisecond, 300*time.Millisecond
	os.Exit(m.Run())
}

// ---- processo auxiliar: o proprio binario de teste age como um modulo ----

func TestHelperProcess(t *testing.T) {
	if !testmod.Enabled() {
		return
	}
	testmod.Main()
}

// ---- infraestrutura de teste ----

func spec(id string, env ...string) config.ModuleSpec {
	return config.ModuleSpec{
		ID: id, Path: os.Args[0], Args: []string{"-test.run=^TestHelperProcess$"},
		Env:        append([]string{"PSY_HELPER=1"}, env...),
		MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
		StableAfter: 10 * time.Second, ConnectTimeout: 2 * time.Second, StopGrace: 2 * time.Second,
	}
}

type env struct {
	sup  *Supervisor
	srv  *ipc.Server
	sock string
	stop func()
}

func setup(t *testing.T, allowUnmanaged bool, specs ...config.ModuleSpec) *env {
	t.Helper()
	return setupOptions(t, Options{Specs: specs, AllowUnmanaged: allowUnmanaged, UIDs: ipc.NewUIDPolicy(uint32(os.Geteuid()), nil)})
}

func setupOptions(t *testing.T, opt Options) *env {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "core.sock")
	opt.SocketPath = sock
	sup := New(opt)
	srv, err := ipc.NewServer(ipc.ServerConfig{
		Path: sock, Auth: sup, Handler: ipc.Handlers(sup),
		StatusInterval: time.Second, CommandTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Skipf("unix sockets indisponiveis: %v", err)
	}
	sctx, scancel := context.WithCancel(context.Background())
	go srv.Serve(sctx)
	rctx, rcancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { sup.Run(rctx); close(runDone) }()

	var once sync.Once
	e := &env{sup: sup, srv: srv, sock: sock}
	e.stop = func() {
		once.Do(func() {
			rcancel()
			select {
			case <-runDone:
			case <-time.After(10 * time.Second):
				t.Error("supervisor.Run nao terminou")
			}
			scancel()
			srv.Shutdown()
		})
	}
	t.Cleanup(e.stop)
	return e
}

func eventually(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout esperando: %s", what)
}

func (e *env) state(id string) psychoscopev1.EstadoModulo {
	i, _ := e.sup.Get(id)
	return i.State
}

func (e *env) waitState(t *testing.T, id string, want psychoscopev1.EstadoModulo) {
	t.Helper()
	eventually(t, 10*time.Second, id+" -> "+want.String(), func() bool { return e.state(id) == want })
}

func processGone(pid int) bool { return syscall.Kill(pid, 0) == syscall.ESRCH }

// ---- testes ----

func TestModuleStartsAndConnects(t *testing.T) {
	e := setup(t, false, spec("mod-a"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	eventually(t, 5*time.Second, "status recebido", func() bool {
		i, _ := e.sup.Get("mod-a")
		return i.LastStatus != nil && i.LastStatus.EventosProcessados == 42
	})
	i, _ := e.sup.Get("mod-a")
	if i.PID == 0 || i.Restarts != 0 || i.LastContact.IsZero() {
		t.Fatalf("info inesperada: %+v", i)
	}
	if i.ModuleVersion != "testmod" || i.ConnectedSince.IsZero() || time.Since(i.ConnectedSince) > time.Minute {
		t.Fatalf("versao e inicio da conexao esperados com o modulo conectado: %+v", i)
	}
	if len(e.sup.List()) != 1 {
		t.Fatal("List")
	}
	if _, ok := e.sup.Get("nope"); ok {
		t.Fatal("Get de modulo inexistente")
	}
}

func TestCrashIsRestartedAndReconnects(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "crashed")
	e := setup(t, false, spec("mod-a", "PSY_CRASH_ONCE_FILE="+flag))
	eventually(t, 10*time.Second, "reinicio apos crash", func() bool {
		i, _ := e.sup.Get("mod-a")
		return i.Restarts >= 1 && i.State == psychoscopev1.EstadoModulo_ESTADO_CONECTADO
	})
	i, _ := e.sup.Get("mod-a")
	if i.LastError == "" {
		t.Errorf("LastError deveria registrar o motivo da queda: %+v", i)
	}
}

func TestDisconnectedModuleHasNoVersionOrConnectionStart(t *testing.T) {
	e := setup(t, false, spec("mod-a", "PSY_NOCONNECT=1"))
	eventually(t, 5*time.Second, "processo lancado", func() bool {
		i, _ := e.sup.Get("mod-a")
		return i.PID != 0
	})
	if i, _ := e.sup.Get("mod-a"); i.ModuleVersion != "" || !i.ConnectedSince.IsZero() {
		t.Fatalf("sem conexao nao ha versao nem inicio: %+v", i)
	}
}

func TestNeverConnectingModuleIsKilledAndRestarted(t *testing.T) {
	s := spec("mod-a", "PSY_NOCONNECT=1")
	s.ConnectTimeout = 300 * time.Millisecond
	e := setup(t, false, s)
	eventually(t, 10*time.Second, "primeiro restart", func() bool {
		i, _ := e.sup.Get("mod-a")
		return i.Restarts >= 1
	})
	i, _ := e.sup.Get("mod-a")
	if i.LastError == "" {
		t.Errorf("LastError vazio: %+v", i)
	}
}

func TestMissingBinaryEntersFailedWithBackoff(t *testing.T) {
	s := spec("mod-a")
	s.Path = "/nonexistent/binary"
	e := setup(t, false, s)
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_FALHOU)
	eventually(t, 5*time.Second, "tentativas repetidas", func() bool {
		i, _ := e.sup.Get("mod-a")
		return i.Restarts >= 2
	})
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	b := 50 * time.Millisecond
	var seq []time.Duration
	for i := 0; i < 5; i++ {
		seq = append(seq, b)
		b = nextBackoff(b, 200*time.Millisecond)
	}
	want := []time.Duration{50, 100, 200, 200, 200}
	for i := range want {
		if seq[i] != want[i]*time.Millisecond {
			t.Fatalf("backoff[%d]=%v want %v", i, seq[i], want[i]*time.Millisecond)
		}
	}
}

func TestPauseResumeAndNack(t *testing.T) {
	e := setup(t, false, spec("mod-a", "PSY_NACK=RECONFIGURAR"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	ctx := context.Background()

	if err := e.sup.Command(ctx, "mod-a", psychoscopev1.ComandoControle_PAUSAR, nil); err != nil {
		t.Fatal(err)
	}
	if e.state("mod-a") != psychoscopev1.EstadoModulo_ESTADO_PAUSADO {
		t.Fatalf("estado %v", e.state("mod-a"))
	}
	if err := e.sup.Command(ctx, "mod-a", psychoscopev1.ComandoControle_RETOMAR, nil); err != nil {
		t.Fatal(err)
	}
	if e.state("mod-a") != psychoscopev1.EstadoModulo_ESTADO_CONECTADO {
		t.Fatalf("estado %v", e.state("mod-a"))
	}
	err := e.sup.Command(ctx, "mod-a", psychoscopev1.ComandoControle_RECONFIGURAR, map[string]string{"iface": "eth9"})
	if !errors.Is(err, ipc.ErrNack) {
		t.Fatalf("esperado NACK, obtido %v", err)
	}
	if err := e.sup.Command(ctx, "ghost", psychoscopev1.ComandoControle_PAUSAR, nil); !errors.Is(err, ErrUnknownModule) {
		t.Fatalf("modulo desconhecido: %v", err)
	}
	if err := e.sup.Command(ctx, "mod-a", psychoscopev1.ComandoControle_ACAO_DESCONHECIDA, nil); err == nil {
		t.Fatal("acao desconhecida deve falhar")
	}
}

func TestCommandWithoutSession(t *testing.T) {
	s := spec("mod-a", "PSY_NOCONNECT=1")
	e := setup(t, false, s)
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_INICIANDO)
	for _, acao := range []psychoscopev1.ComandoControle_TipoAcao{psychoscopev1.ComandoControle_PAUSAR, psychoscopev1.ComandoControle_RETOMAR} {
		if err := e.sup.Command(context.Background(), "mod-a", acao, nil); !errors.Is(err, ErrNotConnected) {
			t.Fatalf("%v: esperado ErrNotConnected, obtido %v", acao, err)
		}
	}
	if i, _ := e.sup.Get("mod-a"); i.Restarts != 0 {
		t.Fatalf("RETOMAR de modulo vivo nao deve relancar: %+v", i)
	}
}

func TestGracefulStopViaEncerrar(t *testing.T) {
	e := setup(t, false, spec("mod-a"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	i, _ := e.sup.Get("mod-a")
	start := time.Now()
	if err := e.sup.Command(context.Background(), "mod-a", psychoscopev1.ComandoControle_ENCERRAR, nil); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Errorf("parada graciosa demorou %v (deveria sair por ENCERRAR, sem sinais)", time.Since(start))
	}
	if e.state("mod-a") != psychoscopev1.EstadoModulo_ESTADO_ENCERRADO || !processGone(i.PID) {
		t.Fatalf("estado=%v processo vivo=%v", e.state("mod-a"), !processGone(i.PID))
	}
	time.Sleep(300 * time.Millisecond)
	if i2, _ := e.sup.Get("mod-a"); i2.Restarts != 0 || i2.State != psychoscopev1.EstadoModulo_ESTADO_ENCERRADO {
		t.Fatalf("modulo encerrado nao deve reiniciar: %+v", i2)
	}
}

func TestStopEscalatesToSIGTERM(t *testing.T) {
	s := spec("mod-a", "PSY_IGNORE_ENCERRAR=1")
	s.StopGrace = 200 * time.Millisecond
	e := setup(t, false, s)
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	i, _ := e.sup.Get("mod-a")
	if err := e.sup.Stop(context.Background(), "mod-a"); err != nil {
		t.Fatal(err)
	}
	if !processGone(i.PID) || e.state("mod-a") != psychoscopev1.EstadoModulo_ESTADO_ENCERRADO {
		t.Fatal("processo deveria ter morrido por SIGTERM")
	}
}

func TestStopEscalatesToSIGKILL(t *testing.T) {
	s := spec("mod-a", "PSY_IGNORE_ENCERRAR=1", "PSY_IGNORE_TERM=1")
	s.StopGrace = 200 * time.Millisecond
	e := setup(t, false, s)
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	i, _ := e.sup.Get("mod-a")
	start := time.Now()
	if err := e.sup.Stop(context.Background(), "mod-a"); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 450*time.Millisecond {
		t.Errorf("escalonamento rapido demais (%v): SIGKILL deveria vir so apos StopGrace+termGrace", el)
	}
	if !processGone(i.PID) {
		t.Fatal("processo deveria ter morrido por SIGKILL")
	}
}

func TestRunCancelStopsAllModules(t *testing.T) {
	e := setup(t, false, spec("mod-a"), spec("mod-b"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	e.waitState(t, "mod-b", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	a, _ := e.sup.Get("mod-a")
	b, _ := e.sup.Get("mod-b")
	e.stop()
	if !processGone(a.PID) || !processGone(b.PID) {
		t.Fatal("filhos nao podem sobreviver ao Run")
	}
}

func TestAuthorizePolicy(t *testing.T) {
	e := setup(t, false, spec("mod-a", "PSY_NOCONNECT=1"))
	// o estado INICIANDO vem antes de o PID do filho ser registrado: espera pelos dois
	eventually(t, 10*time.Second, "filho lancado, sem conexao", func() bool {
		i, _ := e.sup.Get("mod-a")
		return i.State == psychoscopev1.EstadoModulo_ESTADO_INICIANDO && i.PID != 0
	})
	child, _ := e.sup.Get("mod-a")
	if child.PID == 0 { // o filho tem de seguir vivo (PSY_NOCONNECT) enquanto as autorizacoes sao conferidas
		t.Fatal("o filho deveria estar vivo, com PID registrado")
	}
	uid := uint32(os.Geteuid())
	h := func(id string) *psychoscopev1.HelloModulo { return &psychoscopev1.HelloModulo{IdModulo: id} }

	cases := []struct {
		name string
		id   string
		cred ipc.PeerCred
		ok   bool
	}{
		{"filho legitimo", "mod-a", ipc.PeerCred{PID: int32(child.PID), UID: uid}, true},
		{"outro pid usando id gerenciado", "mod-a", ipc.PeerCred{PID: int32(child.PID) + 1, UID: uid}, false},
		{"uid nao permitido", "mod-a", ipc.PeerCred{PID: int32(child.PID), UID: uid + 12345}, false},
		{"modulo nao configurado", "intruso", ipc.PeerCred{PID: 1, UID: uid}, false},
	}
	for _, c := range cases {
		if err := e.sup.Authorize(h(c.id), c.cred); (err == nil) != c.ok {
			t.Errorf("%s: err=%v ok=%v", c.name, err, c.ok)
		}
	}

	open := setup(t, true)
	if err := open.sup.Authorize(h("qualquer"), ipc.PeerCred{PID: 1, UID: uid}); err != nil {
		t.Errorf("AllowUnmanaged deveria aceitar: %v", err)
	}
	if err := open.sup.Authorize(h("qualquer"), ipc.PeerCred{PID: 1, UID: uid + 1}); err == nil {
		t.Error("AllowUnmanaged ainda deve checar UID")
	}
}

func TestImpostorCannotTakeManagedModuleID(t *testing.T) {
	e := setup(t, false, spec("mod-a", "PSY_NOCONNECT=1"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_INICIANDO)

	// Este processo de teste (pid != filho) tenta se passar por mod-a.
	c, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = ipc.WriteMessage(c, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Hello{Hello: &psychoscopev1.HelloModulo{
		IdModulo: "mod-a", VersaoProtocolo: ipc.ProtocolVersion, Pid: uint32(os.Getpid())}}})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := ipc.ReadMessage(c, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := m.GetHelloResposta(); r == nil || r.Aceito || r.MensagemErro != "nao autorizado" {
		t.Fatalf("impostor deveria ser recusado: %v", m)
	}
	if _, ok := e.srv.Session("mod-a"); ok {
		t.Fatal("nao deve haver sessao")
	}
}

func TestChildEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("SEGREDO_DO_CORE", "x")
	sup := New(Options{SocketPath: "/s.sock"})
	cmd := sup.buildCmd(config.ModuleSpec{ID: "mod-a", Path: "/bin/true", Env: []string{"A=1"}})
	got := map[string]bool{}
	for _, kv := range cmd.Env {
		got[kv] = true
	}
	for _, want := range []string{"PSYCHOSCOPE_SOCKET=/s.sock", "PSYCHOSCOPE_MODULE_ID=mod-a", "A=1"} {
		if !got[want] {
			t.Errorf("faltando %s em %v", want, cmd.Env)
		}
	}
	for _, kv := range cmd.Env {
		if kv == "SEGREDO_DO_CORE=x" {
			t.Error("o ambiente do Core nao deve vazar para o filho")
		}
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Error("filho deve ter grupo de processos proprio")
	}
}

func TestResumeRestartsStoppedModule(t *testing.T) {
	e := setup(t, false, spec("mod-a"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	ctx := context.Background()
	prev, _ := e.sup.Get("mod-a")

	// parar -> retomar -> parar -> retomar: cada ciclo tem processo novo e sem restart por crash.
	for range 2 {
		if err := e.sup.Command(ctx, "mod-a", psychoscopev1.ComandoControle_ENCERRAR, nil); err != nil {
			t.Fatal(err)
		}
		if e.state("mod-a") != psychoscopev1.EstadoModulo_ESTADO_ENCERRADO || !processGone(prev.PID) {
			t.Fatalf("estado=%v", e.state("mod-a"))
		}
		if err := e.sup.Command(ctx, "mod-a", psychoscopev1.ComandoControle_RETOMAR, nil); err != nil {
			t.Fatalf("RETOMAR de modulo encerrado: %v", err)
		}
		e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
		cur, _ := e.sup.Get("mod-a")
		if cur.PID == 0 || cur.PID == prev.PID || cur.Restarts != 0 {
			t.Fatalf("esperado processo novo sem restarts: antes=%+v depois=%+v", prev, cur)
		}
		prev = cur
	}
	// o modulo religado volta a aceitar comandos normais.
	if err := e.sup.Command(ctx, "mod-a", psychoscopev1.ComandoControle_PAUSAR, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCommandOnStoppedModuleExplainsHowToStart(t *testing.T) {
	e := setup(t, false, spec("mod-a"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	if err := e.sup.Stop(context.Background(), "mod-a"); err != nil {
		t.Fatal(err)
	}
	err := e.sup.Command(context.Background(), "mod-a", psychoscopev1.ComandoControle_PAUSAR, nil)
	if !errors.Is(err, ErrStopped) {
		t.Fatalf("esperado ErrStopped, obtido %v", err)
	}
}

func TestConcurrentResumeLaunchesOnce(t *testing.T) {
	e := setup(t, false, spec("mod-a"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	if err := e.sup.Stop(context.Background(), "mod-a"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range cap(results) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- e.sup.Command(context.Background(), "mod-a", psychoscopev1.ComandoControle_RETOMAR, nil)
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrNotConnected) {
			t.Fatalf("erro inesperado: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("exatamente um RETOMAR deve relancar, obtido %d", ok)
	}
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
}

func TestResumeAfterShutdownDoesNotLaunch(t *testing.T) {
	e := setup(t, false, spec("mod-a"))
	e.waitState(t, "mod-a", psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	i, _ := e.sup.Get("mod-a")
	e.stop()
	if !processGone(i.PID) {
		t.Fatal("filho deveria ter sido encerrado")
	}
	err := e.sup.Command(context.Background(), "mod-a", psychoscopev1.ComandoControle_RETOMAR, nil)
	if err == nil {
		t.Fatal("RETOMAR com o supervisor encerrado deve falhar")
	}
	if i2, _ := e.sup.Get("mod-a"); i2.PID != 0 {
		t.Fatalf("nenhum processo novo era esperado: %+v", i2)
	}
}
