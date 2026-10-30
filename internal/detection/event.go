// Package detection contem o motor de deteccao: janela deslizante em memoria sobre a
// telemetria dos modulos, regras (interface Rule) e roteamento de alertas.
package detection

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// Kind e a variante de um Event; cada regra declara a que consome (Rule.Kind).
type Kind int

const (
	// KindNet e o evento de fluxo de rede (EventoFluxoRede).
	KindNet Kind = iota + 1
	// KindGeneric e o evento generico de um modulo sem variante propria (EventoGenerico).
	KindGeneric
)

// Event e um evento de um modulo normalizado para o motor. Exatamente um dos campos de variante
// esta preenchido, o que Kind informa; os demais sao nil.
type Event struct {
	Module string
	// At e o instante informado pelo modulo (ou o de chegada, se ausente).
	// O relogio da janela segue os instantes dos eventos, nao o relogio do sistema:
	// replays de pcap antigos se comportam exatamente como trafego ao vivo.
	At      time.Time
	Net     *psychoscopev1.EventoFluxoRede
	Generic *psychoscopev1.EventoGenerico
}

// Kind devolve a variante do evento, ou zero se nenhuma esta preenchida (o motor o ignora).
func (e *Event) Kind() Kind {
	switch {
	case e.Net != nil:
		return KindNet
	case e.Generic != nil:
		return KindGeneric
	}
	return 0
}

// NewEvent normaliza um EventoFluxoRede. arrival e usado quando o sensor nao informou timestamp.
func NewEvent(module string, n *psychoscopev1.EventoFluxoRede, arrival time.Time) *Event {
	return &Event{Module: module, At: instant(n.GetTimestampCaptura(), arrival), Net: n}
}

// Limites do EventoGenerico (os de tamanho estao no ipc.proto).
const (
	maxGenericAttrs     = 32
	maxGenericNameLen   = 64
	maxGenericValueSize = 256
	// maxGenericSkew e o quanto o timestamp de um evento generico pode estar a frente da chegada.
	// O relogio da janela segue os instantes dos eventos, entao um modulo com timestamp no futuro
	// esvaziaria a janela de todos os modulos; alem da tolerancia, o evento e rejeitado.
	maxGenericSkew = 5 * time.Minute
)

var genericNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrInvalidGeneric indica um EventoGenerico fora dos limites do contrato.
var ErrInvalidGeneric = errors.New("evento generico invalido")

// NewGenericEvent normaliza um EventoGenerico depois de conferir os limites do contrato (tipo e
// chaves em [a-z0-9._-] de ate 64 caracteres, ate 32 atributos, valores de ate 256 bytes).
// O timestamp do modulo vale ate maxGenericSkew a frente de arrival; alem disso o evento e
// rejeitado. Devolve ErrInvalidGeneric (embrulhado, com o motivo) se algo for violado.
func NewGenericEvent(module string, g *psychoscopev1.EventoGenerico, arrival time.Time) (*Event, error) {
	if err := validateGeneric(g); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGeneric, err)
	}
	at := instant(g.GetTimestamp(), arrival)
	if at.After(arrival.Add(maxGenericSkew)) {
		return nil, fmt.Errorf("%w: timestamp %s mais de %s a frente da chegada", ErrInvalidGeneric, at.UTC().Format(time.RFC3339), maxGenericSkew)
	}
	return &Event{Module: module, At: at, Generic: g}, nil
}

func validateGeneric(g *psychoscopev1.EventoGenerico) error {
	if !genericNameRe.MatchString(g.GetTipo()) {
		return fmt.Errorf("tipo %q fora de [a-z0-9._-] com ate %d caracteres", g.GetTipo(), maxGenericNameLen)
	}
	if n := len(g.GetAtributos()); n > maxGenericAttrs {
		return fmt.Errorf("%d atributos (maximo %d)", n, maxGenericAttrs)
	}
	for k, v := range g.GetAtributos() {
		if !genericNameRe.MatchString(k) {
			return fmt.Errorf("chave de atributo %q fora de [a-z0-9._-] com ate %d caracteres", k, maxGenericNameLen)
		}
		if len(v) > maxGenericValueSize {
			return fmt.Errorf("valor do atributo %q com %d bytes (maximo %d)", k, len(v), maxGenericValueSize)
		}
	}
	return nil
}

// instant devolve o instante de ts, ou arrival se ts for ausente ou zero.
func instant(ts *timestamppb.Timestamp, arrival time.Time) time.Time {
	if ts != nil && (ts.Seconds != 0 || ts.Nanos != 0) {
		return ts.AsTime()
	}
	return arrival
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
