package rules

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bandeira27/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var t0 = time.Unix(1_700_000_000, 0).UTC()

type pub struct {
	mu sync.Mutex
	as []*psychoscopev1.Alerta
}

func (p *pub) Publish(a *psychoscopev1.Alerta) { p.mu.Lock(); p.as = append(p.as, a); p.mu.Unlock() }

func at(sec float64) *timestamppb.Timestamp {
	return timestamppb.New(t0.Add(time.Duration(sec * float64(time.Second))))
}

func syn(sec float64, src, dst string, port uint32) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: src, IpDestino: dst, PortaOrigem: 40000, PortaDestino: port,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_TCP, FlagsTcp: detection.FlagSYN, TimestampCaptura: at(sec)}
}

func dnsQuery(sec float64, client, domain string) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: client, IpDestino: "10.0.0.53", PortaDestino: 53,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_UDP, TimestampCaptura: at(sec),
		MetadadosL7: &psychoscopev1.EventoFluxoRede_Dns{Dns: &psychoscopev1.EventoFluxoRede_MetadadosDNS{DominioConsultado: domain, TipoRegistro: 1}}}
}

func dnsResp(sec float64, client, domain string, rcode uint32) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: "10.0.0.53", IpDestino: client, PortaOrigem: 53,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_UDP, TimestampCaptura: at(sec),
		MetadadosL7: &psychoscopev1.EventoFluxoRede_Dns{Dns: &psychoscopev1.EventoFluxoRede_MetadadosDNS{
			DominioConsultado: domain, TipoRegistro: 1, CodigoResposta: rcode, EhResposta: true}}}
}

func run(t *testing.T, cfg Config, events ...*psychoscopev1.EventoFluxoRede) []*psychoscopev1.Alerta {
	t.Helper()
	rs, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &pub{}
	e := detection.NewEngine(detection.EngineConfig{Window: time.Minute, QueueSize: len(events) + 1}, rs, p)
	for _, ev := range events {
		if !e.Submit("mod-net-sensor", ev) {
			t.Fatal("fila cheia no teste")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run esvazia a fila e retorna
	e.Run(ctx)
	return p.as
}

func names(as []*psychoscopev1.Alerta) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Regra+"/"+a.Contexto["tipo"])
	}
	return out
}

// ---- varredura ----

func TestVerticalScanFiresOnceAtThreshold(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for p := uint32(1); p <= 40; p++ {
		evs = append(evs, syn(float64(p)*0.1, "10.0.0.66", "10.0.0.2", p))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 {
		t.Fatalf("esperado 1 alerta (cooldown evita repeticao), obtido %v", names(as))
	}
	a := as[0]
	if a.Regra != NameScanSYN || a.Contexto["tipo"] != "vertical" || a.Severidade != psychoscopev1.Severidade_SEVERIDADE_MEDIA ||
		a.Contexto["origem"] != "10.0.0.66" || a.Contexto["destino"] != "10.0.0.2" || a.Contexto["portas_distintas"] != "15" ||
		a.Contexto["chave"] != "10.0.0.66" || a.IdModuloOrigem != "mod-net-sensor" {
		t.Fatalf("alerta: %v", a)
	}
	if !strings.HasPrefix(a.Contexto["portas_exemplo"], "1,2,3") {
		t.Fatalf("portas_exemplo: %s", a.Contexto["portas_exemplo"])
	}
}

func TestHorizontalScan(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for h := 1; h <= 30; h++ {
		evs = append(evs, syn(float64(h)*0.1, "10.0.0.66", fmt.Sprintf("10.0.1.%d", h), 22))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Contexto["tipo"] != "horizontal" || as[0].Severidade != psychoscopev1.Severidade_SEVERIDADE_ALTA ||
		as[0].Contexto["porta"] != "22" || as[0].Contexto["hosts_distintos"] != "20" {
		t.Fatalf("alertas: %v %v", names(as), as)
	}
}

func TestScanFalsePositivesAreAvoided(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	// 1) muitas retransmissoes de SYN para o mesmo destino:porta
	for i := 0; i < 200; i++ {
		evs = append(evs, syn(float64(i)*0.01, "10.0.0.5", "10.0.0.2", 443))
	}
	// 2) conexoes normais: SYN+ACK de servidor a muitos clientes nao conta
	for i := 0; i < 50; i++ {
		e := syn(3+float64(i)*0.01, "10.0.0.2", fmt.Sprintf("10.0.2.%d", i), 50000+uint32(i))
		e.FlagsTcp = detection.FlagSYN | detection.FlagACK
		evs = append(evs, e)
	}
	// 3) varredura LENTA: 16 portas, mas espalhadas por mais que a janela de 10s
	for p := uint32(1); p <= 16; p++ {
		evs = append(evs, syn(20+float64(p)*5, "10.0.0.7", "10.0.0.2", p))
	}
	// 4) abaixo do limiar: 14 portas em 1s
	for p := uint32(1); p <= 14; p++ {
		evs = append(evs, syn(200+float64(p)*0.05, "10.0.0.8", "10.0.0.2", p))
	}
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("nao deveria alertar: %v", names(as))
	}
}

func TestScannersAreTrackedIndependently(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for p := uint32(1); p <= 20; p++ {
		evs = append(evs, syn(float64(p)*0.1, "10.0.0.66", "10.0.0.2", p), syn(float64(p)*0.1+0.01, "10.0.0.67", "10.0.0.3", p))
	}
	as := run(t, Default(), evs...)
	if len(as) != 2 || as[0].Contexto["origem"] == as[1].Contexto["origem"] {
		t.Fatalf("esperado um alerta por origem: %v", as)
	}
}

func TestScanRealertsAfterCooldown(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for round := 0; round < 2; round++ {
		base := float64(round) * 120 // cooldown padrao: 60s
		for p := uint32(1); p <= 20; p++ {
			evs = append(evs, syn(base+float64(p)*0.1, "10.0.0.66", "10.0.0.2", p))
		}
	}
	if as := run(t, Default(), evs...); len(as) != 2 {
		t.Fatalf("esperado re-alerta apos o cooldown: %d", len(as))
	}
}

// ---- NXDOMAIN ----

func TestNXDomainBurst(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 12; i++ {
		evs = append(evs, dnsResp(float64(i), "10.0.0.9", fmt.Sprintf("xk%dqz.example.com", i), 3))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 {
		t.Fatalf("alertas: %v", names(as))
	}
	a := as[0]
	if a.Regra != NameDNSNXDomain || a.Contexto["cliente"] != "10.0.0.9" || a.Contexto["resolvedor"] != "10.0.0.53" ||
		a.Contexto["dominios_distintos"] != "10" || a.Severidade != psychoscopev1.Severidade_SEVERIDADE_MEDIA {
		t.Fatalf("alerta: %v", a)
	}
}

func TestNXDomainFalsePositives(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	// mesmo dominio inexistente consultado em loop (typo/app quebrado): poucos dominios distintos
	for i := 0; i < 50; i++ {
		evs = append(evs, dnsResp(float64(i)*0.2, "10.0.0.9", "typo.example.com", 3))
	}
	// SERVFAIL/NOERROR nao contam
	for i := 0; i < 30; i++ {
		evs = append(evs, dnsResp(float64(i)*0.2, "10.0.0.10", fmt.Sprintf("d%d.example.com", i), uint32(2*(i%2))))
	}
	// NXDOMAIN espalhado em mais tempo que a janela de 30s
	for i := 0; i < 12; i++ {
		evs = append(evs, dnsResp(100+float64(i)*10, "10.0.0.11", fmt.Sprintf("s%d.example.com", i), 3))
	}
	// consultas (nao respostas) com rcode 3 no campo nao existem; consulta comum nao conta
	evs = append(evs, dnsQuery(0, "10.0.0.12", "ok.example.com"))
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("nao deveria alertar: %v", names(as))
	}
}

// ---- tunel DNS ----

func randLabel(rng *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567" // base32
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

func TestDNSTunnelDetected(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 8; i++ {
		evs = append(evs, dnsQuery(float64(i), "10.0.0.9", randLabel(rng, 48)+".t.evil-tunnel.com"))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 {
		t.Fatalf("alertas: %v", names(as))
	}
	a := as[0]
	if a.Regra != NameDNSTunnel || a.Contexto["dominio_base"] != "evil-tunnel.com" || a.Contexto["cliente"] != "10.0.0.9" ||
		a.Contexto["consultas_distintas"] != "5" || a.Severidade != psychoscopev1.Severidade_SEVERIDADE_ALTA {
		t.Fatalf("alerta: %v", a)
	}
}

func TestDNSTunnelFalsePositives(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 20; i++ { // dominios curtos e comuns
		evs = append(evs, dnsQuery(float64(i), "10.0.0.9", fmt.Sprintf("www%d.example.com", i)))
	}
	for i := 0; i < 20; i++ { // reverso: rotulos de 1 caractere
		evs = append(evs, dnsQuery(float64(i), "10.0.0.9", "1.0.0.10.in-addr.arpa"))
		evs = append(evs, dnsQuery(float64(i), "10.0.0.9", strings.Repeat("a.", 30)+"ip6.arpa"))
	}
	for i := 0; i < 20; i++ { // rotulo longo mas de baixa entropia
		evs = append(evs, dnsQuery(float64(i), "10.0.0.9", strings.Repeat("a", 40)+fmt.Sprint(i)+".lowentropy.com"))
	}
	for i := 0; i < 4; i++ { // abaixo do minimo de consultas distintas
		evs = append(evs, dnsQuery(float64(i), "10.0.0.20", randLabel(rng, 48)+".few.example.net"))
	}
	for i := 0; i < 10; i++ { // base permitida
		evs = append(evs, dnsQuery(float64(i), "10.0.0.21", randLabel(rng, 48)+".cdn.allowed.com"))
	}
	cfg := Default()
	cfg.Tunnel.AllowedBases = []string{"allowed.com"}
	for i := 0; i < 20; i++ { // respostas nunca disparam a regra de tunel
		evs = append(evs, dnsResp(float64(i), "10.0.0.22", randLabel(rng, 48)+".resp.example.org", 0))
	}
	if as := run(t, cfg, evs...); len(as) != 0 {
		t.Fatalf("nao deveria alertar: %v", names(as))
	}
}

func TestDisabledRulesAndConfigValidation(t *testing.T) {
	cfg := Default()
	cfg.Disabled = []string{NameScanSYN}
	rs, err := Build(cfg)
	if err != nil || len(rs) != 2 {
		t.Fatalf("regras: %d %v", len(rs), err)
	}
	var evs []*psychoscopev1.EventoFluxoRede
	for p := uint32(1); p <= 40; p++ {
		evs = append(evs, syn(float64(p)*0.1, "10.0.0.66", "10.0.0.2", p))
	}
	if as := run(t, cfg, evs...); len(as) != 0 {
		t.Fatal("regra desabilitada nao pode alertar")
	}

	cfg.Disabled = []string{"net.inexistente"}
	if _, err := Build(cfg); err == nil {
		t.Fatal("nome desconhecido deve falhar")
	}
	bad := Default()
	bad.Scan.VerticalPorts = 0
	if _, err := Build(bad); err == nil {
		t.Fatal("limiar zero deve falhar")
	}
}

func TestSplitDomainAndEntropy(t *testing.T) {
	cases := map[string][2]string{
		"a.b.example.com":   {"example.com", "a.b"},
		"example.com":       {"example.com", ""},
		"x.y.example.co.uk": {"example.co.uk", "x.y"},
		"example.co.uk":     {"example.co.uk", ""},
		"WWW.Example.COM.":  {"example.com", "www"},
		"localhost":         {"localhost", ""},
		"deep.sub.a.com.br": {"a.com.br", "deep.sub"},
	}
	for in, want := range cases {
		if b, s := splitDomain(in); b != want[0] || s != want[1] {
			t.Errorf("splitDomain(%q) = %q,%q want %v", in, b, s, want)
		}
	}
	if entropy("aaaaaaaa") != 0 || entropy("") != 0 {
		t.Error("entropia de texto constante deve ser 0")
	}
	if e := entropy("abcdefgh"); e < 2.99 || e > 3.01 {
		t.Errorf("entropia de 8 simbolos distintos = %v, esperado 3", e)
	}
}
