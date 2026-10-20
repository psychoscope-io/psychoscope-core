// Package detection contem o motor de deteccao: janela deslizante em memoria sobre a
// telemetria dos modulos, regras (interface Rule) e roteamento de alertas.
package detection

import (
	"time"

	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
)

// Flags TCP do campo EventoFluxoRede.flags_tcp.
const (
	FlagFIN uint32 = 0x01
	FlagSYN uint32 = 0x02
	FlagRST uint32 = 0x04
	FlagPSH uint32 = 0x08
	FlagACK uint32 = 0x10
	FlagURG uint32 = 0x20
)

// Event e um evento de fluxo de rede normalizado para o motor.
type Event struct {
	Module string
	// At e o instante de captura informado pelo sensor (ou o de chegada, se ausente).
	// O relogio da janela segue os instantes dos eventos, nao o relogio do sistema:
	// replays de pcap antigos se comportam exatamente como trafego ao vivo.
	At  time.Time
	Net *psychoscopev1.EventoFluxoRede
}

// NewEvent normaliza um EventoFluxoRede. arrival e usado quando o sensor nao informou timestamp.
func NewEvent(module string, n *psychoscopev1.EventoFluxoRede, arrival time.Time) *Event {
	at := arrival
	if ts := n.GetTimestampCaptura(); ts != nil && (ts.Seconds != 0 || ts.Nanos != 0) {
		at = ts.AsTime()
	}
	return &Event{Module: module, At: at, Net: n}
}

// DNS devolve os metadados DNS do evento (nil se nao for DNS).
func (e *Event) DNS() *psychoscopev1.EventoFluxoRede_MetadadosDNS { return e.Net.GetDns() }

// TLS devolve os metadados TLS do evento (nil se nao for TLS).
func (e *Event) TLS() *psychoscopev1.EventoFluxoRede_MetadadosTLS { return e.Net.GetTls() }

// IsTCP informa se o evento e TCP.
func (e *Event) IsTCP() bool {
	return e.Net.GetProtocolo() == psychoscopev1.ProtocoloTransporte_PROTO_TCP
}

// IsPureSYN informa se e um segmento TCP com SYN e sem ACK (abertura de conexao / sonda).
func (e *Event) IsPureSYN() bool {
	return e.IsTCP() && e.Net.FlagsTcp&FlagSYN != 0 && e.Net.FlagsTcp&FlagACK == 0
}
