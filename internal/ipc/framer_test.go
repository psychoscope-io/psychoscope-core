package ipc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/iotest"

	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type vectorFile struct {
	MaxFrameSize uint32 `json:"max_frame_size"`
	Cases        []struct {
		Name        string `json:"name"`
		Header      string `json:"header"`
		Payload     string `json:"payload"`
		PayloadFill *struct {
			Byte  string `json:"byte"`
			Count int    `json:"count"`
		} `json:"payload_fill"`
		Expect string `json:"expect"`
	} `json:"cases"`
}

type vectorCase struct {
	name    string
	stream  []byte // header + payload, exatamente como vai ao fio
	payload []byte // payload esperado (casos ok)
	expect  string
}

func loadVectors(t testing.TB) (uint32, []vectorCase) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/framing_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	var out []vectorCase
	for _, c := range vf.Cases {
		hdr, err := hex.DecodeString(c.Header)
		if err != nil {
			t.Fatalf("%s: header: %v", c.Name, err)
		}
		var payload []byte
		switch {
		case c.PayloadFill != nil:
			b, err := hex.DecodeString(c.PayloadFill.Byte)
			if err != nil || len(b) != 1 {
				t.Fatalf("%s: byte invalido", c.Name)
			}
			payload = bytes.Repeat(b, c.PayloadFill.Count)
		case c.Payload != "":
			if payload, err = hex.DecodeString(c.Payload); err != nil {
				t.Fatalf("%s: payload: %v", c.Name, err)
			}
		}
		out = append(out, vectorCase{
			name:    c.Name,
			stream:  append(append([]byte{}, hdr...), payload...),
			payload: payload,
			expect:  c.Expect,
		})
	}
	return vf.MaxFrameSize, out
}

func checkExpect(t *testing.T, expect string, payload, want []byte, err error) {
	t.Helper()
	switch expect {
	case "ok":
		if err != nil {
			t.Fatalf("erro inesperado: %v", err)
		}
		if !bytes.Equal(payload, want) {
			t.Fatalf("payload diferente (len %d vs %d)", len(payload), len(want))
		}
	case "eof":
		if err != io.EOF {
			t.Fatalf("esperado io.EOF, obtido %v", err)
		}
	case "empty":
		if !errors.Is(err, ErrEmptyFrame) {
			t.Fatalf("esperado ErrEmptyFrame, obtido %v", err)
		}
	case "too_large":
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("esperado ErrFrameTooLarge, obtido %v", err)
		}
	case "truncated":
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("esperado io.ErrUnexpectedEOF, obtido %v", err)
		}
	default:
		t.Fatalf("expect desconhecido: %q", expect)
	}
}

func TestGoldenVectors(t *testing.T) {
	max, cases := loadVectors(t)
	if max != MaxFrameSize {
		t.Fatalf("max_frame_size dos vetores (%d) != MaxFrameSize (%d)", max, MaxFrameSize)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ReadFrame(bytes.NewReader(c.stream), 0)
			checkExpect(t, c.expect, got, c.payload, err)
		})
		// Mesmo resultado quando o stream chega fragmentado byte a byte.
		t.Run(c.name+"/one_byte_reader", func(t *testing.T) {
			got, err := ReadFrame(iotest.OneByteReader(bytes.NewReader(c.stream)), 0)
			checkExpect(t, c.expect, got, c.payload, err)
		})
		if c.expect == "ok" {
			t.Run(c.name+"/write", func(t *testing.T) {
				var buf bytes.Buffer
				if err := WriteFrame(&buf, c.payload); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf.Bytes(), c.stream) {
					t.Fatalf("bytes escritos != vetor canonico")
				}
			})
		}
	}
}

// countingReader conta bytes consumidos para provar que frames inválidos
// são rejeitados sem ler o payload.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestOversizedRejectedBeforeReadingPayload(t *testing.T) {
	stream := append([]byte{0x00, 0x10, 0x00, 0x01}, make([]byte, 4096)...)
	cr := &countingReader{r: bytes.NewReader(stream)}
	_, err := ReadFrame(cr, 0)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("esperado ErrFrameTooLarge, obtido %v", err)
	}
	if cr.n != HeaderSize {
		t.Fatalf("consumiu %d bytes; esperado apenas o header (%d)", cr.n, HeaderSize)
	}
}

func TestCustomMaxIsHonoredAndClamped(t *testing.T) {
	frame := append([]byte{0, 0, 0, 8}, make([]byte, 8)...)
	if _, err := ReadFrame(bytes.NewReader(frame), 7); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("max=7 deveria rejeitar frame de 8: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(frame), 8); err != nil {
		t.Fatalf("max=8 deveria aceitar: %v", err)
	}
	huge := []byte{0x00, 0x10, 0x00, 0x01}
	if _, err := ReadFrame(bytes.NewReader(huge), 1<<30); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("max acima de MaxFrameSize deve ser limitado: %v", err)
	}
}

func TestWriteFrameRejectsInvalid(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, nil); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("payload vazio: %v", err)
	}
	if err := WriteFrame(&buf, make([]byte, MaxFrameSize+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("payload grande: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("nada deveria ser escrito, escritos %d bytes", buf.Len())
	}
}

func sampleMessage() *psychoscopev1.MensagemIPC {
	return &psychoscopev1.MensagemIPC{
		IdMensagem: "msg-1",
		Timestamp:  timestamppb.Now(),
		Payload: &psychoscopev1.MensagemIPC_Telemetria{Telemetria: &psychoscopev1.EventoTelemetria{
			IdModulo: "mod-net-sensor",
			Dado: &psychoscopev1.EventoTelemetria_Rede{Rede: &psychoscopev1.EventoFluxoRede{
				IpOrigem: "10.0.0.1", PortaOrigem: 51514,
				IpDestino: "1.1.1.1", PortaDestino: 53,
				Protocolo:    psychoscopev1.ProtocoloTransporte_PROTO_UDP,
				TamanhoBytes: 74,
				MetadadosL7: &psychoscopev1.EventoFluxoRede_Dns{Dns: &psychoscopev1.EventoFluxoRede_MetadadosDNS{
					DominioConsultado: "example.com", TipoRegistro: 1,
				}},
				FlagsTcp: 0x12,
			}},
		}},
	}
}

func TestMessageRoundTripOverUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sock := dir + "/t.sock"
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets indisponiveis: %v", err)
	}
	defer ln.Close()

	want := sampleMessage()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		got, err := ReadMessage(c, 0)
		if err != nil {
			done <- err
			return
		}
		if !proto.Equal(got, want) {
			done <- errors.New("mensagem recebida difere da enviada")
			return
		}
		done <- WriteMessage(c, got) // eco
	}()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := WriteMessage(c, want); err != nil {
		t.Fatal(err)
	}
	echo, err := ReadMessage(c, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(echo, want) {
		t.Fatal("eco difere")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReadMessageGarbagePayload(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, []byte{0xff, 0xff, 0xff}) // protobuf invalido
	if _, err := ReadMessage(&buf, 0); err == nil {
		t.Fatal("esperado erro de unmarshal")
	}
}

func FuzzReadFrame(f *testing.F) {
	_, cases := loadVectors(f)
	for _, c := range cases {
		if len(c.stream) < 64<<10 { // evita seeds gigantes
			f.Add(c.stream)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := ReadFrame(bytes.NewReader(data), 0)
		if err != nil {
			if payload != nil {
				t.Fatal("payload nao-nil junto com erro")
			}
			return
		}
		if len(payload) == 0 || uint32(len(payload)) > MaxFrameSize {
			t.Fatalf("payload fora dos limites: %d", len(payload))
		}
		var buf bytes.Buffer
		if err := WriteFrame(&buf, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), data[:buf.Len()]) {
			t.Fatal("round-trip nao reproduz os bytes do fio")
		}
	})
}
