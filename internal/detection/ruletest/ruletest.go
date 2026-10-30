// Package ruletest reune o que quem escreve uma regra de deteccao precisa para testa-la sem subir o
// Core: construtores de eventos de rede e genericos num tempo controlado (T0 mais segundos), um
// executor que passa os eventos por um motor de verdade e um teste de tabela que confere os alertas.
// Importa so o pacote detection; e usado apenas em testes.
package ruletest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// T0 e o instante zero dos eventos construidos aqui; At(sec) conta a partir dele.
var T0 = time.Unix(1_700_000_000, 0).UTC()

// DefaultWindow e a duracao da janela do motor usada por Run e Table.
const DefaultWindow = time.Minute

// At devolve o instante T0 + sec segundos.
func At(sec float64) *timestamppb.Timestamp {
	return timestamppb.New(T0.Add(time.Duration(sec * float64(time.Second))))
}

// Input e um evento a entregar ao motor: de rede (Net) ou generico (Generic), exatamente um dos dois.
// Module e o modulo de origem; vazio vale "mod-net-sensor" para rede e "mod-test" para generico.
type Input struct {
	Module  string
	Net     *psychoscopev1.EventoFluxoRede
	Generic *psychoscopev1.EventoGenerico
}

// Net embrulha um evento de rede.
func Net(ev *psychoscopev1.EventoFluxoRede) Input { return Input{Net: ev} }

// Nets embrulha varios eventos de rede, na ordem.
func Nets(evs ...*psychoscopev1.EventoFluxoRede) []Input {
	out := make([]Input, len(evs))
	for i, ev := range evs {
		out[i] = Net(ev)
	}
	return out
}

// Gen monta um evento generico no instante At(sec) com os atributos dados (pode ser nil).
func Gen(sec float64, tipo string, attrs map[string]string) Input {
	return Input{Generic: &psychoscopev1.EventoGenerico{Tipo: tipo, Timestamp: At(sec), Atributos: attrs}}
}

// SYN e um segmento TCP SYN puro (sonda de abertura de conexao) de src para dst:port.
func SYN(sec float64, src, dst string, port uint32) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: src, IpDestino: dst, PortaOrigem: 40000, PortaDestino: port,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_TCP, FlagsTcp: detection.FlagSYN, TimestampCaptura: At(sec)}
}

// DNSQuery e uma consulta DNS (tipo A) de client ao resolvedor 10.0.0.53.
func DNSQuery(sec float64, client, domain string) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: client, IpDestino: "10.0.0.53", PortaDestino: 53,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_UDP, TimestampCaptura: At(sec),
		MetadadosL7: &psychoscopev1.EventoFluxoRede_Dns{Dns: &psychoscopev1.EventoFluxoRede_MetadadosDNS{DominioConsultado: domain, TipoRegistro: 1}}}
}

// DNSResponse e a resposta DNS do resolvedor 10.0.0.53 a client, com o codigo de resposta rcode.
func DNSResponse(sec float64, client, domain string, rcode uint32) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: "10.0.0.53", IpDestino: client, PortaOrigem: 53,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_UDP, TimestampCaptura: At(sec),
		MetadadosL7: &psychoscopev1.EventoFluxoRede_Dns{Dns: &psychoscopev1.EventoFluxoRede_MetadadosDNS{
			DominioConsultado: domain, TipoRegistro: 1, CodigoResposta: rcode, EhResposta: true}}}
}

// TLSHello e um ClientHello TLS de client a dst:443 com o SNI e a versao dados.
func TLSHello(sec float64, client, dst, sni, version string) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: client, IpDestino: dst, PortaOrigem: 50000, PortaDestino: 443,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_TCP, FlagsTcp: detection.FlagPSH | detection.FlagACK, TimestampCaptura: At(sec),
		MetadadosL7: &psychoscopev1.EventoFluxoRede_Tls{Tls: &psychoscopev1.EventoFluxoRede_MetadadosTLS{SniHostname: sni, VersaoTls: version}}}
}

// ICMP e um pacote ICMP de src para dst com o tipo dado (8 = echo request).
func ICMP(sec float64, src, dst string, typ uint32) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: src, IpDestino: dst, Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_ICMP,
		IcmpTipo: typ, TimestampCaptura: At(sec)}
}

type collector struct {
	mu sync.Mutex
	as []*psychoscopev1.Alerta
}

func (c *collector) Publish(a *psychoscopev1.Alerta) {
	c.mu.Lock()
	c.as = append(c.as, a)
	c.mu.Unlock()
}

// Run entrega os eventos, na ordem, a um motor de verdade com as regras dadas e devolve os alertas
// publicados. Falha o teste se um evento for rejeitado ou a fila encher.
func Run(t *testing.T, rules []detection.Rule, in ...Input) []*psychoscopev1.Alerta {
	t.Helper()
	pub := &collector{}
	eng := detection.NewEngine(detection.EngineConfig{Window: DefaultWindow, QueueSize: len(in) + 1}, rules, pub)
	for i, ev := range in {
		if err := submit(eng, ev); err != nil {
			t.Fatalf("evento %d: %v", i, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run esvazia a fila antes de voltar
	eng.Run(ctx)
	return pub.as
}

func submit(eng *detection.Engine, in Input) error {
	switch {
	case in.Net != nil:
		module := in.Module
		if module == "" {
			module = "mod-net-sensor"
		}
		if !eng.Submit(module, in.Net) {
			return detection.ErrQueueFull
		}
	case in.Generic != nil:
		module := in.Module
		if module == "" {
			module = "mod-test"
		}
		return eng.SubmitGeneric(module, in.Generic)
	}
	return nil
}

// Want descreve um alerta esperado: a regra e, opcionalmente, chaves do contexto (so as listadas
// sao conferidas) e a severidade (zero = nao conferir).
type Want struct {
	Rule     string
	Context  map[string]string
	Severity psychoscopev1.Severidade
}

// Case e uma linha do teste de tabela: os eventos entregues, na ordem, e os alertas esperados, na
// ordem em que foram publicados. Want vazio significa "nenhum alerta" (caso de falso positivo).
type Case struct {
	Name   string
	Inputs []Input
	Want   []Want
}

// Table roda cada caso com regras novas (build e chamada uma vez por caso, para que o estado de um
// caso nao vaze para o seguinte) e confere a quantidade, a regra e o contexto dos alertas.
func Table(t *testing.T, build func(t *testing.T) []detection.Rule, cases []Case) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			got := Run(t, build(t), c.Inputs...)
			if len(got) != len(c.Want) {
				t.Fatalf("esperava %d alerta(s), vieram %d: %s", len(c.Want), len(got), describe(got))
			}
			for i, w := range c.Want {
				checkAlert(t, i, got[i], w)
			}
		})
	}
}

func checkAlert(t *testing.T, i int, got *psychoscopev1.Alerta, w Want) {
	t.Helper()
	if got.Regra != w.Rule {
		t.Errorf("alerta %d: regra %q, esperada %q", i, got.Regra, w.Rule)
	}
	if w.Severity != 0 && got.Severidade != w.Severity {
		t.Errorf("alerta %d: severidade %v, esperada %v", i, got.Severidade, w.Severity)
	}
	for k, v := range w.Context {
		if got.Contexto[k] != v {
			t.Errorf("alerta %d: contexto[%q]=%q, esperado %q", i, k, got.Contexto[k], v)
		}
	}
}

func describe(as []*psychoscopev1.Alerta) string {
	if len(as) == 0 {
		return "nenhum"
	}
	s := ""
	for _, a := range as {
		s += "\n  " + a.Regra + ": " + a.Descricao
	}
	return s
}
