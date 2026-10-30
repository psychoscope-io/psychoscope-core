package rules

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	"github.com/psychoscope-io/psychoscope-core/internal/detection/ruletest"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Os construtores de eventos e o executor vivem em ruletest, para que toda regra os reuse.
var (
	at       = ruletest.At
	syn      = ruletest.SYN
	dnsQuery = ruletest.DNSQuery
	dnsResp  = ruletest.DNSResponse
)

func run(t *testing.T, cfg Config, events ...*psychoscopev1.EventoFluxoRede) []*psychoscopev1.Alerta {
	t.Helper()
	rs, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ruletest.Run(t, rs, ruletest.Nets(events...)...)
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
		as[0].Contexto["porta"] != "22" || as[0].Contexto["sem_resposta"] != "20" || as[0].Contexto["hosts_distintos"] != "30" {
		t.Fatalf("alertas: %v %v", names(as), as)
	}
}

// synAck e a resposta SYN+ACK do servidor (porta serverPort) ao cliente.
func synAck(sec float64, server, client string, serverPort uint32) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: server, IpDestino: client, PortaOrigem: serverPort, PortaDestino: 40000,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_TCP, FlagsTcp: detection.FlagSYN | detection.FlagACK, TimestampCaptura: at(sec)}
}

// browserBurst: cliente abre n conexoes na 443 para hosts distintos, a cada step s, e cada
// servidor responde SYN-ACK rtt s depois (o que um navegador carregando uma pagina faz). Os
// eventos saem em ordem de tempo, como o sensor os entrega.
func browserBurst(n int, step, rtt float64) []*psychoscopev1.EventoFluxoRede {
	var evs []*psychoscopev1.EventoFluxoRede
	for h := 1; h <= n; h++ {
		host := fmt.Sprintf("203.0.113.%d", h)
		evs = append(evs, syn(float64(h)*step, "192.168.0.8", host, 443), synAck(float64(h)*step+rtt, host, "192.168.0.8", 443))
	}
	sortByTime(evs)
	return evs
}

func TestHorizontalScanIgnoresHostsThatAnswered(t *testing.T) {
	// 60 hosts na 443 em 6 s, todos com handshake completo: navegador, nao varredura
	if as := run(t, Default(), browserBurst(60, 0.1, 0.05)...); len(as) != 0 {
		t.Fatalf("destinos que responderam SYN-ACK nao sao varredura: %v", names(as))
	}
	// rajada muito rapida (30 hosts em 0,3 s) com ida e volta de 0,5 s: ao avaliar cada sonda
	// nenhuma resposta chegou ainda, mas as sondas novas nao contam como sem resposta
	evs := append(browserBurst(30, 0.01, 0.5), syn(5, "192.168.0.8", "203.0.113.200", 443))
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("rajada rapida com respostas nao e varredura: %v", names(as))
	}
}

func TestHorizontalScanStillFiresWithoutAnswers(t *testing.T) {
	// 30 hosts na 443, nenhum responde: varredura. A ultima sonda de cada 1 s ainda esta "a caminho".
	var evs []*psychoscopev1.EventoFluxoRede
	for h := 1; h <= 30; h++ {
		evs = append(evs, syn(float64(h)*0.1, "10.0.0.66", fmt.Sprintf("203.0.113.%d", h), 443))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Contexto["tipo"] != "horizontal" || as[0].Contexto["porta"] != "443" {
		t.Fatalf("varredura da 443 sem respostas deve alertar: %v", as)
	}
	// um RST nao e SYN-ACK: o host existe mas a porta nao, tipico de varredura
	for h := 1; h <= 30; h++ {
		rst := synAck(float64(h)*0.1+0.02, fmt.Sprintf("203.0.113.%d", h), "10.0.0.66", 443)
		rst.FlagsTcp = detection.FlagRST | detection.FlagACK
		evs = append(evs, rst)
	}
	if as := run(t, Default(), evs...); len(as) != 1 {
		t.Fatalf("RST nao conta como resposta: %v", names(as))
	}
}

func TestHorizontalScanCountsOnlyUnansweredAndNeedsAFollowUpProbe(t *testing.T) {
	// 40 hosts que responderam (0,02 s entre sondas) misturados a 25 que nao (de 0,3 s a 0,54 s)
	evs := browserBurst(40, 0.02, 0.05)
	for h := 1; h <= 25; h++ {
		evs = append(evs, syn(0.29+float64(h)*0.01, "192.168.0.8", fmt.Sprintf("198.51.100.%d", h), 443))
	}
	sortByTime(evs)
	// ate aqui toda sonda tem menos de 1 s: ainda pode estar a caminho da resposta, e nada alerta
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("sondas com menos de 1 s nao contam como sem resposta: %v", names(as))
	}
	// outra sonda da mesma origem, 2 s depois, avalia a janela: so os 25 sem resposta contam
	evs = append(evs, syn(2, "192.168.0.8", "203.0.113.250", 443))
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Contexto["sem_resposta"] != "25" || as[0].Contexto["hosts_distintos"] != "66" {
		t.Fatalf("40 que responderam nao contam; 25 sem resposta sim (66 sondados): %v", as)
	}
	// uma resposta de OUTRO host (ou de outra porta) nao conta como resposta
	var wrong []*psychoscopev1.EventoFluxoRede
	for h := 1; h <= 30; h++ {
		wrong = append(wrong, syn(float64(h)*0.1, "10.0.0.66", fmt.Sprintf("203.0.113.%d", h), 443),
			synAck(float64(h)*0.1+0.02, "203.0.113.250", "10.0.0.66", 443), // sempre o mesmo servidor, que nao foi sondado
			synAck(float64(h)*0.1+0.03, fmt.Sprintf("203.0.113.%d", h), "10.0.0.66", 8443))
	}
	sortByTime(wrong)
	if as := run(t, Default(), wrong...); len(as) != 1 {
		t.Fatalf("resposta de outro host ou porta nao isenta a sonda: %v", names(as))
	}
}

func TestTLSAllowedBasesValidation(t *testing.T) {
	for _, ok := range [][]string{nil, {"example.com"}, {"blob.core.windows.net", "online-metrix.net."}} {
		cfg := Default()
		cfg.TLS.AllowedBases = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("%v devia valer: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "net", "com", ".example.com", "a b.com", "a.com,b.com"} {
		cfg := Default()
		cfg.TLS.AllowedBases = []string{bad}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "detection.tls.allowed_bases") {
			t.Errorf("%q devia ser recusado citando o campo, veio %v", bad, err)
		}
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

// Reverse DNS de redes privadas (varias redes Docker ao ligar a maquina) gera NXDOMAIN
// para muitos nomes distintos: nao e DGA e nao deve alertar com a configuracao padrao.
func reverseLookups(n int) []*psychoscopev1.EventoFluxoRede {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < n; i++ {
		evs = append(evs, dnsResp(float64(i), "192.168.0.8", fmt.Sprintf("1.0.%d.172.in-addr.arpa", 17+i), 3))
	}
	return evs
}

func TestNXDomainIgnoresReverseZonesByDefault(t *testing.T) {
	if as := run(t, Default(), reverseLookups(10)...); len(as) != 0 {
		t.Fatalf("DNS reverso nao deve alertar: %v", names(as))
	}
	// IPv6 e caixa/ponto final diferentes tambem sao ignorados
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 12; i++ {
		evs = append(evs, dnsResp(float64(i), "192.168.0.8", fmt.Sprintf("%x.0.0.0.IP6.ARPA.", i), 3))
	}
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("ip6.arpa com maiusculas e ponto final nao deve alertar: %v", names(as))
	}
}

func TestNXDomainReverseZonesDoNotMaskARealBurst(t *testing.T) {
	// 9 reversos + 9 nomes diretos aleatorios: so os diretos contam, e 9 < min_responses (10)
	evs := reverseLookups(9)
	for i := 0; i < 9; i++ {
		evs = append(evs, dnsResp(float64(20+i)*0.5, "192.168.0.8", fmt.Sprintf("xk%dqz.example.com", i), 3))
	}
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("reversos nao somam para o limiar: %v", names(as))
	}
	// com 12 nomes diretos o DGA continua sendo detectado, mesmo misturado ao reverso
	for i := 9; i < 12; i++ {
		evs = append(evs, dnsResp(float64(20+i)*0.5, "192.168.0.8", fmt.Sprintf("xk%dqz.example.com", i), 3))
	}
	as := run(t, Default(), evs...)
	// o alerta sai no 10o nome direto (limiar), e os exemplos nao incluem nenhum reverso
	if len(as) != 1 || as[0].Contexto["dominios_distintos"] != "10" || strings.Contains(as[0].Contexto["dominios_exemplo"], "arpa") {
		t.Fatalf("DGA misturado ao DNS reverso deve alertar so com os nomes diretos: %v", as)
	}
}

// srvLookups sao n consultas SRV de descoberta de servico (o que o apt faz) que voltam NXDOMAIN.
func srvLookups(n int) []*psychoscopev1.EventoFluxoRede {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < n; i++ {
		evs = append(evs, dnsResp(float64(i)*0.5, "192.168.0.8", fmt.Sprintf("_https._tcp.host%d.example.com", i), 3))
	}
	return evs
}

func TestNXDomainIgnoresServiceDiscoveryNames(t *testing.T) {
	if as := run(t, Default(), srvLookups(30)...); len(as) != 0 {
		t.Fatalf("consultas SRV (_https._tcp.*) nao sao DGA: %v", names(as))
	}
}

func TestNXDomainServiceDiscoveryDoesNotMaskARealBurst(t *testing.T) {
	// 9 nomes diretos aleatorios mais 30 SRV: so os diretos contam, e 9 < min_responses (10)
	evs := srvLookups(30)
	for i := 0; i < 9; i++ {
		evs = append(evs, dnsResp(float64(20+i)*0.5, "192.168.0.8", fmt.Sprintf("xk%dqz.example.com", i), 3))
	}
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("SRV nao somam para o limiar: %v", names(as))
	}
	// com 12 nomes diretos o DGA continua sendo detectado, misturado aos SRV
	for i := 9; i < 12; i++ {
		evs = append(evs, dnsResp(float64(20+i)*0.5, "192.168.0.8", fmt.Sprintf("xk%dqz.example.com", i), 3))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Contexto["dominios_distintos"] != "10" || strings.Contains(as[0].Contexto["dominios_exemplo"], "_https") {
		t.Fatalf("DGA misturado a SRV deve alertar so com os nomes diretos: %v", as)
	}
}

func TestNXDomainEmptyIgnoreSuffixesCountsEverything(t *testing.T) {
	cfg := Default()
	cfg.NXDomain.IgnoreSuffixes = nil
	if as := run(t, cfg, reverseLookups(10)...); len(as) != 1 {
		t.Fatalf("sem ignore_suffixes o reverso volta a contar: %v", names(as))
	}
}

func TestNXDomainIgnoreSuffixesValidation(t *testing.T) {
	for _, bad := range []string{"", ".arpa", "in addr.arpa", "a.com,b.com"} {
		c := Default()
		c.NXDomain.IgnoreSuffixes = []string{bad}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ignore_suffixes") {
			t.Errorf("sufixo %q deveria ser recusado: %v", bad, err)
		}
	}
	c := Default()
	c.NXDomain.IgnoreSuffixes = []string{"corp.example", "in-addr.arpa"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
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
	if err != nil || len(rs) != len(AllNames())-1 {
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
