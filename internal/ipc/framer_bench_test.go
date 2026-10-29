package ipc

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"path/filepath"
	"testing"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// telemetryFrame e um frame de telemetria de rede (consulta DNS), do tamanho de um evento real.
func telemetryFrame(tb testing.TB) []byte {
	tb.Helper()
	var buf bytes.Buffer
	err := WriteMessage(&buf, &psychoscopev1.MensagemIPC{
		IdMensagem: "bench", Timestamp: timestamppb.Now(),
		Payload: &psychoscopev1.MensagemIPC_Telemetria{Telemetria: &psychoscopev1.EventoTelemetria{
			IdModulo: "mod-net-sensor",
			Dado: &psychoscopev1.EventoTelemetria_Rede{Rede: &psychoscopev1.EventoFluxoRede{
				IpOrigem: "192.168.0.8", IpDestino: "192.168.0.1", PortaOrigem: 51000, PortaDestino: 53,
				Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_UDP, TamanhoBytes: 74,
				TimestampCaptura: timestamppb.Now(),
				MetadadosL7: &psychoscopev1.EventoFluxoRede_Dns{Dns: &psychoscopev1.EventoFluxoRede_MetadadosDNS{
					DominioConsultado: "h12.bench.example.com", TipoRegistro: 1,
				}},
			}},
		}},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

// BenchmarkReadMessage mede so a desserializacao de um frame (sem I/O): o piso do custo por evento
// na leitura do Core.
func BenchmarkReadMessage(b *testing.B) {
	frame := telemetryFrame(b)
	r := bytes.NewReader(frame)
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Reset(frame)
		if _, err := ReadMessage(r, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadMessageSocket le frames de um socket Unix real, como o readLoop do servidor, para
// um escritor que envia lotes de 64 eventos por escrita (como o cliente IPC do sensor): "direto"
// le do net.Conn (cada ReadMessage faz duas leituras, cabecalho e corpo) e "bufio" poe um
// bufio.Reader entre o socket e o decodificador.
func BenchmarkReadMessageSocket(b *testing.B) {
	for _, mode := range []string{"direto", "bufio"} {
		b.Run(mode, func(b *testing.B) {
			frame := telemetryFrame(b)
			batch := bytes.Repeat(frame, 64)
			sock := filepath.Join(b.TempDir(), "bench.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := net.Dial("unix", sock)
				if err != nil {
					return
				}
				defer c.Close()
				for {
					if _, err := c.Write(batch); err != nil {
						return
					}
				}
			}()
			conn, err := ln.Accept()
			if err != nil {
				b.Fatal(err)
			}
			var r io.Reader = conn
			if mode == "bufio" {
				r = bufio.NewReaderSize(conn, 64<<10)
			}
			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := ReadMessage(r, 0); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			conn.Close()
			<-done
		})
	}
}
