package ruletest

import (
	"strconv"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// loginBurst e uma regra generica de exemplo: dispara quando um mesmo usuario acumula 3 eventos
// "login.falha" na janela. Serve de modelo para testar uma regra de modulo que nao e de rede.
type loginBurst struct{}

func (loginBurst) Name() string         { return "teste.login_burst" }
func (loginBurst) Kind() detection.Kind { return detection.KindGeneric }
func (loginBurst) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	user := ev.Generic.GetAtributos()["usuario"]
	n := 0
	for _, e := range w.OfType("login.falha") {
		if e.Module == ev.Module && e.Generic.GetAtributos()["usuario"] == user {
			n++
		}
	}
	if ev.Generic.GetTipo() != "login.falha" || n < 3 {
		return nil
	}
	return detection.NewAlert("teste.login_burst", psychoscopev1.Severidade_SEVERIDADE_ALTA,
		"muitas falhas de login de "+user+": "+strconv.Itoa(n), ev, map[string]string{"usuario": user, "falhas": strconv.Itoa(n)})
}

func buildLoginBurst(*testing.T) []detection.Rule { return []detection.Rule{loginBurst{}} }

func fail(sec float64, user string) Input {
	return Gen(sec, "login.falha", map[string]string{"usuario": user})
}

func TestTableWithAGenericRule(t *testing.T) {
	Table(t, buildLoginBurst, []Case{
		{"abaixo do limiar nao dispara", []Input{fail(0, "ana"), fail(1, "ana")}, nil},
		{"no limiar dispara uma vez", []Input{fail(0, "ana"), fail(1, "ana"), fail(2, "ana")},
			[]Want{{Rule: "teste.login_burst", Severity: psychoscopev1.Severidade_SEVERIDADE_ALTA, Context: map[string]string{"usuario": "ana", "falhas": "3"}}}},
		{"usuarios diferentes nao se somam", []Input{fail(0, "ana"), fail(1, "bia"), fail(2, "ana"), fail(3, "bia")}, nil},
		{"outro tipo de evento nao conta", []Input{fail(0, "ana"), fail(1, "ana"), Gen(2, "login.ok", map[string]string{"usuario": "ana"})}, nil},
		{"falhas fora da janela nao contam", []Input{fail(0, "ana"), fail(1, "ana"), fail(200, "ana")}, nil},
		{"outro modulo nao se soma", []Input{fail(0, "ana"), {Module: "mod-b", Generic: fail(1, "ana").Generic}, fail(2, "ana")}, nil},
	})
}

func TestRunMixesNetworkAndGenericInputs(t *testing.T) {
	rules := []detection.Rule{loginBurst{}}
	in := append(Nets(SYN(0, "10.0.0.9", "10.0.0.2", 22), ICMP(1, "10.0.0.9", "10.0.0.2", 8)),
		fail(2, "ana"), fail(3, "ana"), fail(4, "ana"))
	if as := Run(t, rules, in...); len(as) != 1 || as[0].Regra != "teste.login_burst" || as[0].IdModuloOrigem != "mod-test" {
		t.Fatalf("alertas: %v", as)
	}
}

func TestBuildersProduceTheEventsRulesExpect(t *testing.T) {
	if ev := SYN(1.5, "a", "b", 22); ev.FlagsTcp != detection.FlagSYN || ev.PortaDestino != 22 ||
		!ev.TimestampCaptura.AsTime().Equal(T0.Add(1500*time.Millisecond)) {
		t.Errorf("SYN: %v", ev)
	}
	if ev := DNSResponse(0, "c", "x.example", 3); !ev.GetDns().EhResposta || ev.GetDns().CodigoResposta != 3 || ev.IpDestino != "c" {
		t.Errorf("DNSResponse: %v", ev)
	}
	if ev := TLSHello(0, "c", "d", "sni.example", "TLS1.3"); ev.GetTls().SniHostname != "sni.example" || ev.PortaDestino != 443 {
		t.Errorf("TLSHello: %v", ev)
	}
	if ev := ICMP(0, "a", "b", 8); ev.IcmpTipo != 8 || ev.Protocolo != psychoscopev1.ProtocoloTransporte_PROTO_ICMP {
		t.Errorf("ICMP: %v", ev)
	}
}
