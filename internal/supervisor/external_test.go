package supervisor

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Os testes de modulo External usam este processo de teste como o "servico do systemd": o UID
// do teste e o do usuario configurado, e o PID nao importa (o Core nao lancou o processo).

func externalSpec(id string) config.ModuleSpec {
	sp := spec(id)
	sp.External, sp.User, sp.Path, sp.Args, sp.Env = true, "psychoscope-sensor", "", nil, nil
	return sp
}

func externalOptions(id string, uid uint32) Options {
	return Options{
		Specs: []config.ModuleSpec{externalSpec(id)}, ExternalUIDs: map[string]uint32{id: uid},
		UIDs: ipc.NewUIDPolicy(uint32(os.Geteuid()), []uint32{uid}), //nolint:gosec // UID do kernel nao e negativo
	}
}

func TestExternalModuleIsNotLaunched(t *testing.T) {
	e := setupOptions(t, externalOptions("mod-ext", uint32(os.Geteuid()))) //nolint:gosec // UID do kernel nao e negativo
	time.Sleep(300 * time.Millisecond)                                     // espaco para um lancamento indevido aparecer
	i, ok := e.sup.Get("mod-ext")
	if !ok || i.PID != 0 || i.Restarts != 0 || i.State != psychoscopev1.EstadoModulo_ESTADO_INICIANDO {
		t.Errorf("modulo externo deve ficar aguardando, sem processo: %+v", i)
	}
}

func TestAuthorizeExternalNeedsExactUID(t *testing.T) {
	euid := uint32(os.Geteuid()) //nolint:gosec // UID do kernel nao e negativo
	h := &psychoscopev1.HelloModulo{IdModulo: "mod-ext"}
	cases := []struct {
		name string
		opt  Options
		cred ipc.PeerCred
		ok   bool
	}{
		{"uid configurado, qualquer pid", externalOptions("mod-ext", euid), ipc.PeerCred{PID: 424242, UID: euid}, true},
		{"uid do Core nao basta", externalOptions("mod-ext", euid+777), ipc.PeerCred{PID: 1, UID: euid}, false},
		{"root nao basta", externalOptions("mod-ext", euid+777), ipc.PeerCred{PID: 1, UID: 0}, false},
		{"uid configurado, politica diferente", externalOptions("mod-ext", euid+777), ipc.PeerCred{PID: 1, UID: euid + 777}, true},
	}
	noUID := externalOptions("mod-ext", euid)
	noUID.ExternalUIDs = nil
	cases = append(cases, struct {
		name string
		opt  Options
		cred ipc.PeerCred
		ok   bool
	}{"uid nao resolvido recusa", noUID, ipc.PeerCred{PID: 1, UID: euid}, false})
	for _, c := range cases {
		if err := New(c.opt).Authorize(h, c.cred); (err == nil) != c.ok {
			t.Errorf("%s: err=%v ok=%v", c.name, err, c.ok)
		}
	}
}

// dialExternal conecta como o modulo e devolve a conexao e uma funcao que responde ao proximo comando.
func dialExternal(t *testing.T, e *env, id string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = ipc.WriteMessage(c, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Hello{Hello: &psychoscopev1.HelloModulo{
		IdModulo: id, VersaoProtocolo: ipc.ProtocolVersion, Pid: uint32(os.Getpid())}}}) //nolint:gosec // PID do kernel cabe em uint32
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := ipc.ReadMessage(c, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := m.GetHelloResposta(); r == nil || !r.Aceito {
		t.Fatalf("hello deveria ser aceito: %v", m)
	}
	return c
}

func TestExternalConnectDisconnectAndStop(t *testing.T) {
	const id = "mod-ext"
	e := setupOptions(t, externalOptions(id, uint32(os.Geteuid()))) //nolint:gosec // UID do kernel nao e negativo
	c := dialExternal(t, e, id)
	e.waitState(t, id, psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	if i, _ := e.sup.Get(id); i.PID != os.Getpid() {
		t.Errorf("PID vem do kernel (SO_PEERCRED): %d", i.PID)
	}

	// queda inesperada: o systemd o reinicia, entao o estado volta a "iniciando"
	c.Close()
	e.waitState(t, id, psychoscopev1.EstadoModulo_ESTADO_INICIANDO)
	if i, _ := e.sup.Get(id); i.PID != 0 {
		t.Errorf("sem sessao nao ha PID: %d", i.PID)
	}

	// ENCERRAR confirmado e depois a desconexao: encerrado, nao "iniciando"
	c = dialExternal(t, e, id)
	e.waitState(t, id, psychoscopev1.EstadoModulo_ESTADO_CONECTADO)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- e.sup.Command(ctx, id, psychoscopev1.ComandoControle_ENCERRAR, nil)
	}()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		m, err := ipc.ReadMessage(c, 0)
		if err != nil {
			t.Fatal(err)
		}
		if cmd := m.GetComando(); cmd != nil {
			if cmd.Acao != psychoscopev1.ComandoControle_ENCERRAR {
				t.Fatalf("acao inesperada: %v", cmd.Acao)
			}
			_ = ipc.WriteMessage(c, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Resposta{Resposta: &psychoscopev1.RespostaComando{
				IdComandoReferencia: cmd.IdComando, Sucesso: true}}})
			break
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("ENCERRAR: %v", err)
	}
	c.Close()
	e.waitState(t, id, psychoscopev1.EstadoModulo_ESTADO_ENCERRADO)
}

func TestExternalCommandsWithoutSessionExplainWhoStartsIt(t *testing.T) {
	const id = "mod-ext"
	e := setupOptions(t, externalOptions(id, uint32(os.Geteuid()))) //nolint:gosec // UID do kernel nao e negativo
	for _, acao := range []psychoscopev1.ComandoControle_TipoAcao{
		psychoscopev1.ComandoControle_ENCERRAR, psychoscopev1.ComandoControle_RETOMAR, psychoscopev1.ComandoControle_PAUSAR,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := e.sup.Command(ctx, id, acao, nil)
		cancel()
		if !errors.Is(err, ErrExternalOffline) {
			t.Errorf("%v sem sessao: err=%v, esperado ErrExternalOffline", acao, err)
		}
	}
}
