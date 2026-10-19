// Comando de desenvolvimento: servidor de interoperabilidade Go <-> Rust.
//
// Uso: ipc-interop --socket S --scenario happy|oversize --dump-sent F --dump-recv F
//
// Remover (ou mover para tests) quando o listener real do Core existir (Fase 3).
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/Bandeira27/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func ts() *timestamppb.Timestamp { return &timestamppb.Timestamp{Seconds: 1700000000, Nanos: 123} }

func main() {
	sock := flag.String("socket", "", "caminho do socket")
	scenario := flag.String("scenario", "happy", "happy|oversize")
	dumpSent := flag.String("dump-sent", "", "arquivo: frames enviados (hex, 1 por linha)")
	dumpRecv := flag.String("dump-recv", "", "arquivo: frames recebidos (hex, 1 por linha)")
	flag.Parse()

	if err := run(*sock, *scenario, *dumpSent, *dumpRecv); err != nil {
		fmt.Fprintln(os.Stderr, "ipc-interop (go) FALHOU:", err)
		os.Exit(1)
	}
	fmt.Println("ipc-interop (go) OK:", *scenario)
}

func run(sock, scenario, dumpSent, dumpRecv string) error {
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("listening", sock) // sinaliza prontidao ao script
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	var sent, recv []string
	defer func() {
		_ = os.WriteFile(dumpSent, []byte(join(sent)), 0o644)
		_ = os.WriteFile(dumpRecv, []byte(join(recv)), 0o644)
	}()

	read := func() (*psychoscopev1.MensagemIPC, error) {
		b, err := ipc.ReadFrame(conn, 0)
		if err != nil {
			return nil, err
		}
		recv = append(recv, fmt.Sprintf("%x", b))
		m := &psychoscopev1.MensagemIPC{}
		return m, proto.Unmarshal(b, m)
	}
	write := func(m *psychoscopev1.MensagemIPC) error {
		b, err := proto.Marshal(m)
		if err != nil {
			return err
		}
		sent = append(sent, fmt.Sprintf("%x", b))
		return ipc.WriteFrame(conn, b)
	}

	if scenario == "oversize" {
		_, err := ipc.ReadFrame(conn, 0)
		if !errors.Is(err, ipc.ErrFrameTooLarge) {
			return fmt.Errorf("esperado ErrFrameTooLarge, obtido %v", err)
		}
		return nil // fecha a conexao (defer) sem ler o payload
	}

	// 1. Hello (Rust -> Go)
	m, err := read()
	if err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	h := m.GetHello()
	if m.IdMensagem != "m-hello" || h == nil || h.IdModulo != "mod-net-sensor" ||
		h.VersaoProtocolo != 1 || h.VersaoModulo != "0.1.0" || h.Pid != 4242 ||
		!proto.Equal(m.Timestamp, ts()) {
		return fmt.Errorf("hello inesperado: %v", m)
	}

	// 2. HelloResposta (Go -> Rust)
	if err := write(&psychoscopev1.MensagemIPC{
		IdMensagem: "m-hello-ack", Timestamp: ts(),
		Payload: &psychoscopev1.MensagemIPC_HelloResposta{HelloResposta: &psychoscopev1.HelloResposta{
			Aceito: true, VersaoCore: "0.1.0", IntervaloStatusSeg: 5,
		}},
	}); err != nil {
		return err
	}

	// 3. Telemetria DNS (Rust -> Go)
	m, err = read()
	if err != nil {
		return fmt.Errorf("telemetria: %w", err)
	}
	r := m.GetTelemetria().GetRede()
	if m.IdMensagem != "m-evt" || r == nil || r.IpOrigem != "10.0.0.1" || r.PortaDestino != 53 ||
		r.Protocolo != psychoscopev1.ProtocoloTransporte_PROTO_UDP || r.TamanhoBytes != 74 ||
		r.GetDns().GetDominioConsultado() != "example.com" ||
		len(r.GetDns().GetRespostasIp()) != 2 || r.FlagsTcp != 0x12 ||
		!proto.Equal(r.TimestampCaptura, ts()) {
		return fmt.Errorf("telemetria inesperada: %v", m)
	}

	// 4. Comando PAUSAR (Go -> Rust)
	if err := write(&psychoscopev1.MensagemIPC{
		IdMensagem: "m-cmd", Timestamp: ts(),
		Payload: &psychoscopev1.MensagemIPC_Comando{Comando: &psychoscopev1.ComandoControle{
			IdComando: "cmd-1", Acao: psychoscopev1.ComandoControle_PAUSAR,
			Parametros: map[string]string{"motivo": "teste"},
		}},
	}); err != nil {
		return err
	}

	// 5. Resposta (Rust -> Go)
	m, err = read()
	if err != nil {
		return fmt.Errorf("resposta: %w", err)
	}
	if rc := m.GetResposta(); rc == nil || rc.IdComandoReferencia != "cmd-1" || !rc.Sucesso {
		return fmt.Errorf("resposta inesperada: %v", m)
	}

	// 6. Fecha a conexao (defer): o Rust deve observar EOF limpo na fronteira de frame.
	return nil
}

func join(lines []string) string {
	s := ""
	for _, l := range lines {
		s += l + "\n"
	}
	return s
}
