// Package testmod e um modulo falso usado APENAS em testes: o binario de teste
// se re-executa como filho do supervisor e fala o protocolo IPC de verdade.
//
// Controle por variaveis de ambiente:
//
//	PSY_NOCONNECT=1         nao conecta (dorme)
//	PSY_CRASH_ONCE_FILE=f   na primeira execucao (f ausente) cria f e sai com 3 apos 150ms
//	PSY_IGNORE_TERM=1       ignora SIGTERM
//	PSY_IGNORE_ENCERRAR=1   confirma ENCERRAR mas nao sai
//	PSY_NACK=<ACAO>         responde NACK a essa acao (ex.: RECONFIGURAR)
package testmod

import (
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Bandeira27/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
)

// Enabled informa se este processo foi lancado como modulo falso.
func Enabled() bool { return os.Getenv("PSY_HELPER") != "" }

// Main executa o modulo falso e nunca retorna.
func Main() {
	if os.Getenv("PSY_IGNORE_TERM") != "" {
		signal.Ignore(syscall.SIGTERM)
	}
	if os.Getenv("PSY_NOCONNECT") != "" {
		select {}
	}
	if f := os.Getenv("PSY_CRASH_ONCE_FILE"); f != "" {
		if _, err := os.Stat(f); err != nil {
			_ = os.WriteFile(f, []byte("x"), 0o600)
			time.AfterFunc(150*time.Millisecond, func() { os.Exit(3) })
		}
	}

	id := os.Getenv("PSYCHOSCOPE_MODULE_ID")
	conn, err := net.Dial("unix", os.Getenv("PSYCHOSCOPE_SOCKET"))
	if err != nil {
		os.Exit(10)
	}
	var wmu sync.Mutex
	send := func(m *psychoscopev1.MensagemIPC) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = ipc.WriteMessage(conn, m)
	}
	send(&psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Hello{Hello: &psychoscopev1.HelloModulo{
		IdModulo: id, VersaoProtocolo: ipc.ProtocolVersion, VersaoModulo: "testmod", Pid: uint32(os.Getpid()),
	}}})
	m, err := ipc.ReadMessage(conn, 0)
	if err != nil || !m.GetHelloResposta().GetAceito() {
		os.Exit(11)
	}
	go func() {
		for {
			send(&psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Status{Status: &psychoscopev1.StatusModulo{IdModulo: id, EventosProcessados: 42}}})
			time.Sleep(50 * time.Millisecond)
		}
	}()
	for {
		m, err := ipc.ReadMessage(conn, 0)
		if err != nil {
			os.Exit(12)
		}
		cmd := m.GetComando()
		if cmd == nil {
			continue
		}
		ok, msg := true, ""
		if os.Getenv("PSY_NACK") == cmd.Acao.String() {
			ok, msg = false, "recusado pelo modulo de teste"
		}
		send(&psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Resposta{Resposta: &psychoscopev1.RespostaComando{
			IdComandoReferencia: cmd.IdComando, Sucesso: ok, MensagemErro: msg}}})
		if ok && cmd.Acao == psychoscopev1.ComandoControle_ENCERRAR && os.Getenv("PSY_IGNORE_ENCERRAR") == "" {
			os.Exit(0)
		}
	}
}
