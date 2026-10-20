package rules

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func tlsHello(sec float64, client, dst, sni, version string) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: client, IpDestino: dst, PortaOrigem: 50000, PortaDestino: 443,
		Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_TCP, FlagsTcp: detection.FlagPSH | detection.FlagACK, TimestampCaptura: at(sec),
		MetadadosL7: &psychoscopev1.EventoFluxoRede_Tls{Tls: &psychoscopev1.EventoFluxoRede_MetadadosTLS{SniHostname: sni, VersaoTls: version}}}
}

func icmp(sec float64, src, dst string, typ uint32) *psychoscopev1.EventoFluxoRede {
	return &psychoscopev1.EventoFluxoRede{IpOrigem: src, IpDestino: dst, Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_ICMP,
		IcmpTipo: typ, TimestampCaptura: at(sec)}
}

func synFrom(sec float64, src, dst string, sport, dport uint32) *psychoscopev1.EventoFluxoRede {
	e := syn(sec, src, dst, dport)
	e.PortaOrigem = sport
	return e
}

func motivos(as []*psychoscopev1.Alerta) []string {
	var o []string
	for _, a := range as {
		o = append(o, a.Contexto["motivo"])
	}
	return o
}

// ---- net.tls.suspicious ----

func TestTLSSuspiciousReasons(t *testing.T) {
	random := "x7k2m9q4w8z1b5n3v6c0.example.com"
	cases := []struct {
		name    string
		ev      *psychoscopev1.EventoFluxoRede
		wantMot string
		wantSev psychoscopev1.Severidade
	}{
		{"SNI e um IP", tlsHello(0, "10.0.0.5", "1.2.3.4", "93.184.216.34", "TLS1.3"), "sni_ip_literal", psychoscopev1.Severidade_SEVERIDADE_MEDIA},
		{"SNI IPv6 entre colchetes", tlsHello(0, "10.0.0.5", "1.2.3.4", "[2001:db8::1]", "TLS1.3"), "sni_ip_literal", psychoscopev1.Severidade_SEVERIDADE_MEDIA},
		{"rotulo aleatorio longo", tlsHello(0, "10.0.0.5", "1.2.3.4", random, "TLS1.3"), "sni_alta_entropia", psychoscopev1.Severidade_SEVERIDADE_MEDIA},
		{"TLS 1.0", tlsHello(0, "10.0.0.5", "1.2.3.4", "legacy.example.com", "TLS1.0"), "versao_obsoleta", psychoscopev1.Severidade_SEVERIDADE_BAIXA},
		{"SSL 3.0", tlsHello(0, "10.0.0.5", "1.2.3.4", "legacy.example.com", "SSL3.0"), "versao_obsoleta", psychoscopev1.Severidade_SEVERIDADE_BAIXA},
		{"prioridade: IP vence versao obsoleta", tlsHello(0, "10.0.0.5", "1.2.3.4", "1.1.1.1", "TLS1.0"), "sni_ip_literal", psychoscopev1.Severidade_SEVERIDADE_MEDIA},
	}
	for _, c := range cases {
		as := run(t, Default(), c.ev)
		if len(as) != 1 || as[0].Regra != NameTLSSuspicious || as[0].Contexto["motivo"] != c.wantMot || as[0].Severidade != c.wantSev ||
			as[0].Contexto["cliente"] != "10.0.0.5" || as[0].Contexto["destino"] != "1.2.3.4" {
			t.Errorf("%s: %v", c.name, as)
		}
	}
}

func TestTLSSuspiciousFalsePositives(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for i, sni := range []string{
		"www.example.com", "api.github.com", "internal-service-gateway.example.com", // hifenado: legivel, mesmo com entropia alta
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com", // longo mas de baixa entropia
		"short.example.com", "static-assets-cdn-production-eu.example.com",
	} {
		evs = append(evs, tlsHello(float64(i), "10.0.0.5", "1.2.3.4", sni, "TLS1.3"), tlsHello(float64(i)+0.5, "10.0.0.6", "1.2.3.4", sni, "TLS1.2"))
	}
	// nao-TLS e TLS sem hello suspeito
	evs = append(evs, dnsQuery(0, "10.0.0.5", "x7k2m9q4w8z1b5n3v6c0.example.com"))
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("nao deveria alertar: %v", motivos(as))
	}

	// base permitida: entropia alta ignorada
	cfg := Default()
	cfg.TLS.AllowedBases = []string{"example.com"}
	if as := run(t, cfg, tlsHello(0, "10.0.0.5", "1.2.3.4", "x7k2m9q4w8z1b5n3v6c0.example.com", "TLS1.3")); len(as) != 0 {
		t.Fatalf("allowed_bases deveria isentar: %v", as)
	}
}

func TestTLSMissingSNINeedsRepetitionWithinWindow(t *testing.T) {
	two := []*psychoscopev1.EventoFluxoRede{tlsHello(0, "10.0.0.5", "1.1.1.1", "", "TLS1.3"), tlsHello(1, "10.0.0.5", "1.1.1.2", "", "TLS1.3")}
	if as := run(t, Default(), two...); len(as) != 0 {
		t.Fatal("2 sem SNI nao bastam")
	}
	three := append(two, tlsHello(2, "10.0.0.5", "1.1.1.3", "", "TLS1.3"))
	as := run(t, Default(), three...)
	if len(as) != 1 || as[0].Contexto["motivo"] != "sni_ausente" || as[0].Contexto["ocorrencias"] != "3" || as[0].Severidade != psychoscopev1.Severidade_SEVERIDADE_BAIXA {
		t.Fatalf("3 sem SNI: %v", as)
	}
	spread := []*psychoscopev1.EventoFluxoRede{tlsHello(0, "10.0.0.5", "1.1.1.1", "", "TLS1.3"), tlsHello(40, "10.0.0.5", "1.1.1.2", "", "TLS1.3"), tlsHello(80, "10.0.0.5", "1.1.1.3", "", "TLS1.3")}
	if as := run(t, Default(), spread...); len(as) != 0 {
		t.Fatal("fora da janela de 60 s nao conta")
	}
	// clientes diferentes nao se somam
	mixed := []*psychoscopev1.EventoFluxoRede{tlsHello(0, "10.0.0.5", "1.1.1.1", "", "TLS1.3"), tlsHello(1, "10.0.0.6", "1.1.1.2", "", "TLS1.3"), tlsHello(2, "10.0.0.7", "1.1.1.3", "", "TLS1.3")}
	if as := run(t, Default(), mixed...); len(as) != 0 {
		t.Fatal("clientes distintos nao somam")
	}
}

func TestTLSCooldownPerClientAndReason(t *testing.T) {
	evs := []*psychoscopev1.EventoFluxoRede{
		tlsHello(0, "10.0.0.5", "1.2.3.4", "9.9.9.9", "TLS1.3"),
		tlsHello(1, "10.0.0.5", "1.2.3.5", "8.8.8.8", "TLS1.3"),        // mesmo motivo/cliente: suprimido
		tlsHello(2, "10.0.0.5", "1.2.3.6", "ok.example.com", "TLS1.0"), // outro motivo: alerta
		tlsHello(3, "10.0.0.6", "1.2.3.4", "9.9.9.9", "TLS1.3"),        // outro cliente: alerta
		tlsHello(700, "10.0.0.5", "1.2.3.4", "9.9.9.9", "TLS1.3"),      // cooldown de 10 min expirou
	}
	as := run(t, Default(), evs...)
	if got := motivos(as); len(as) != 4 || got[0] != "sni_ip_literal" || got[1] != "versao_obsoleta" || got[2] != "sni_ip_literal" {
		t.Fatalf("alertas: %v", got)
	}
}

// ---- net.icmp.sweep ----

func TestICMPSweep(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for h := 1; h <= 30; h++ {
		evs = append(evs, icmp(float64(h)*0.2, "10.0.0.66", fmt.Sprintf("10.0.1.%d", h), 8))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Regra != NameICMPSweep || as[0].Contexto["hosts_distintos"] != "20" || as[0].Contexto["origem"] != "10.0.0.66" ||
		as[0].Severidade != psychoscopev1.Severidade_SEVERIDADE_MEDIA {
		t.Fatalf("alertas: %v", as)
	}

	var v6 []*psychoscopev1.EventoFluxoRede
	for h := 1; h <= 25; h++ {
		v6 = append(v6, icmp(float64(h)*0.1, "fe80::66", fmt.Sprintf("fe80::%x", h), 128))
	}
	if as := run(t, Default(), v6...); len(as) != 1 {
		t.Fatalf("ICMPv6 echo (tipo 128): %d alertas", len(as))
	}
}

func TestICMPSweepFalsePositives(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for h := 1; h <= 40; h++ { // respostas (tipo 0) e destino inalcancavel (3) de muitos hosts
		evs = append(evs, icmp(float64(h)*0.1, fmt.Sprintf("10.0.1.%d", h), "10.0.0.66", 0))
		evs = append(evs, icmp(float64(h)*0.1+0.01, fmt.Sprintf("10.0.2.%d", h), "10.0.0.66", 3))
	}
	for i := 0; i < 100; i++ { // ping continuo ao mesmo host
		evs = append(evs, icmp(float64(i)*0.05, "10.0.0.7", "10.0.0.1", 8))
	}
	for h := 1; h <= 30; h++ { // varredura LENTA: 1 host a cada 5 s (janela de 10 s)
		evs = append(evs, icmp(100+float64(h)*5, "10.0.0.8", fmt.Sprintf("10.0.3.%d", h), 8))
	}
	for h := 1; h <= 19; h++ { // abaixo do limiar
		evs = append(evs, icmp(400+float64(h)*0.1, "10.0.0.9", fmt.Sprintf("10.0.4.%d", h), 8))
	}
	// ICMPv6 com tipo 8 (que em v6 nao e echo) nao conta
	for h := 1; h <= 30; h++ {
		evs = append(evs, icmp(500+float64(h)*0.1, "fe80::9", fmt.Sprintf("fe80::%x", h), 8))
	}
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("nao deveria alertar: %v", names(as))
	}
}

// ---- net.bruteforce.auth ----

func TestBruteForceSSH(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 15; i++ {
		evs = append(evs, synFrom(float64(i), "10.0.0.66", "10.0.0.2", uint32(40000+i), 22))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Regra != NameBruteForce || as[0].Severidade != psychoscopev1.Severidade_SEVERIDADE_ALTA ||
		as[0].Contexto["porta"] != "22" || as[0].Contexto["conexoes"] != "10" || as[0].Contexto["destino"] != "10.0.0.2" {
		t.Fatalf("alertas: %v", as)
	}
}

func TestBruteForceFalsePositives(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 50; i++ { // retransmissoes: mesma porta de origem
		evs = append(evs, synFrom(float64(i)*0.1, "10.0.0.5", "10.0.0.2", 40000, 22))
	}
	for i := 0; i < 30; i++ { // porta que nao e de autenticacao
		evs = append(evs, synFrom(float64(i), "10.0.0.6", "10.0.0.2", uint32(41000+i), 8080))
	}
	for i := 0; i < 12; i++ { // espalhado alem da janela de 30 s
		evs = append(evs, synFrom(float64(i)*10, "10.0.0.7", "10.0.0.2", uint32(42000+i), 3389))
	}
	for i := 0; i < 30; i++ { // um SSH por host: nao e forca bruta contra um alvo
		evs = append(evs, synFrom(float64(i)*0.5, "10.0.0.8", fmt.Sprintf("10.0.9.%d", i), uint32(43000+i), 22))
	}
	for i := 0; i < 9; i++ { // abaixo do limiar
		evs = append(evs, synFrom(float64(i), "10.0.0.9", "10.0.0.2", uint32(44000+i), 445))
	}
	for i := 0; i < 20; i++ { // SYN+ACK de servidor para muitos clientes (nao e SYN puro)
		e := synFrom(float64(i), "10.0.0.2", "10.0.0.10", uint32(22), uint32(45000+i))
		e.FlagsTcp = detection.FlagSYN | detection.FlagACK
		evs = append(evs, e)
	}
	cfg := Default()
	cfg.Disabled = []string{NameBeacon} // o item 3 acima e, de fato, periodico (a cada 10 s): outro teste cobre isso
	if as := run(t, cfg, evs...); len(as) != 0 {
		t.Fatalf("nao deveria alertar: %v", names(as))
	}
}

func TestBruteForceIgnoredSourcesAndCustomPorts(t *testing.T) {
	mk := func(src string, port uint32) []*psychoscopev1.EventoFluxoRede {
		var evs []*psychoscopev1.EventoFluxoRede
		for i := 0; i < 15; i++ {
			evs = append(evs, synFrom(float64(i), src, "10.0.0.2", uint32(40000+i), port))
		}
		return evs
	}
	cfg := Default()
	cfg.BruteForce.IgnoreSources = []string{"10.9.0.0/16", "10.0.0.50"}
	for _, src := range []string{"10.9.3.4", "10.0.0.50"} {
		if as := run(t, cfg, mk(src, 22)...); len(as) != 0 {
			t.Errorf("origem isenta %s nao deve alertar", src)
		}
	}
	if as := run(t, cfg, mk("10.0.0.51", 22)...); len(as) != 1 {
		t.Error("origem nao isenta deve alertar")
	}
	cfg.BruteForce.Ports = []int{6379}
	if as := run(t, cfg, mk("10.0.0.51", 22)...); len(as) != 0 {
		t.Error("22 fora da lista customizada")
	}
	if as := run(t, cfg, mk("10.0.0.51", 6379)...); len(as) != 1 {
		t.Error("porta customizada deve alertar")
	}
}

// ---- net.dns.rate ----

func TestDNSRate(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 260; i++ {
		evs = append(evs, dnsQuery(float64(i)*0.02, "10.0.0.9", fmt.Sprintf("h%d.example.com", i%50)))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Regra != NameDNSRate || as[0].Contexto["consultas"] != "200" || as[0].Contexto["dominios_distintos"] != "50" {
		t.Fatalf("alertas: %v", as)
	}
}

func TestDNSRateFalsePositives(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 150; i++ { // abaixo do limiar
		evs = append(evs, dnsQuery(float64(i)*0.05, "10.0.0.1", "a.example.com"))
	}
	for i := 0; i < 400; i++ { // respostas nao contam
		evs = append(evs, dnsResp(float64(i)*0.02, "10.0.0.2", "a.example.com", 0))
	}
	for i := 0; i < 300; i++ { // 300 consultas em 300 s: ritmo normal
		evs = append(evs, dnsQuery(float64(i), "10.0.0.3", "a.example.com"))
	}
	for c := 0; c < 20; c++ { // muitos clientes, poucos cada
		for i := 0; i < 15; i++ {
			evs = append(evs, dnsQuery(float64(i)*0.1, fmt.Sprintf("10.1.0.%d", c), "a.example.com"))
		}
	}
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("nao deveria alertar: %v", names(as))
	}
}

// ---- net.beacon ----

func beatsTCP(src, dst string, dport uint32, start, every, jitter float64, n int, rng *rand.Rand) []*psychoscopev1.EventoFluxoRede {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < n; i++ {
		j := 0.0
		if jitter > 0 {
			j = (rng.Float64()*2 - 1) * jitter
		}
		evs = append(evs, synFrom(start+float64(i)*every+j, src, dst, uint32(50000+i), dport))
	}
	return evs
}

func TestBeaconTCPRegularWithJitter(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	evs := beatsTCP("10.0.0.5", "203.0.113.7", 443, 0, 30, 3, 12, rng)
	as := run(t, Default(), evs...)
	if len(as) != 1 {
		t.Fatalf("esperado 1 alerta de beacon: %v", names(as))
	}
	a := as[0]
	if a.Regra != NameBeacon || a.Contexto["tipo"] != "tcp" || a.Contexto["alvo"] != "203.0.113.7:443" || a.Contexto["origem"] != "10.0.0.5" ||
		a.Severidade != psychoscopev1.Severidade_SEVERIDADE_MEDIA || a.Contexto["amostras"] != "8" || !durNear(t, a.Contexto["intervalo_medio"], 30*time.Second, 2*time.Second) ||
		a.Contexto["chave"] != "tcp|10.0.0.5|203.0.113.7:443" {
		t.Fatalf("alerta: %v", a)
	}
}

func TestBeaconDNS(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 10; i++ {
		evs = append(evs, dnsQuery(float64(i)*60, "10.0.0.5", "C2.Evil.Example."))
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Contexto["tipo"] != "dns" || as[0].Contexto["alvo"] != "c2.evil.example" {
		t.Fatalf("beacon DNS: %v", as)
	}
}

func TestBeaconCollapsesRetransmissionBursts(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 10; i++ { // cada contato manda o SYN 3 vezes (retransmissao em 1 s e 3 s)
		base := float64(i) * 30
		for k, off := range []float64{0, 1, 3} {
			evs = append(evs, synFrom(base+off, "10.0.0.5", "203.0.113.7", uint32(50000+i), 443+uint32(0*k)))
		}
	}
	as := run(t, Default(), evs...)
	if len(as) != 1 || as[0].Contexto["amostras"] != "8" || !strings.HasPrefix(as[0].Contexto["intervalo_medio"], "30s") {
		t.Fatalf("rajadas devem contar como um contato: %v", as)
	}
}

func TestBeaconFalsePositives(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	var evs []*psychoscopev1.EventoFluxoRede
	// 1) intervalos irregulares (5 a 125 s)
	t0 := 0.0
	for i := 0; i < 20; i++ {
		t0 += 5 + rng.Float64()*120
		evs = append(evs, synFrom(t0, "10.0.0.1", "198.51.100.1", uint32(50000+i), 443))
	}
	// 2) rapido demais: a cada 2 s forma uma unica "rajada" continua
	for i := 0; i < 40; i++ {
		evs = append(evs, synFrom(float64(i)*2, "10.0.0.2", "198.51.100.2", uint32(51000+i), 443))
	}
	// 3) lento demais: a cada 2 h
	for i := 0; i < 10; i++ {
		evs = append(evs, synFrom(float64(i)*7200, "10.0.0.3", "198.51.100.3", uint32(52000+i), 443))
	}
	// 4) poucas amostras regulares
	evs = append(evs, beatsTCP("10.0.0.4", "198.51.100.4", 443, 0, 30, 0, 7, rng)...)
	// 5) mesmo ritmo, mas a ORIGEM e o ALVO mudam a cada contato (nao e uma serie)
	for i := 0; i < 20; i++ {
		evs = append(evs, synFrom(float64(i)*30, fmt.Sprintf("10.2.0.%d", i), fmt.Sprintf("198.51.101.%d", i), uint32(53000+i), 443))
	}
	// 6) SYN+ACK e respostas DNS nao contam
	for i := 0; i < 20; i++ {
		e := synFrom(float64(i)*30, "10.0.0.6", "198.51.100.6", 443, uint32(54000+i))
		e.FlagsTcp = detection.FlagSYN | detection.FlagACK
		evs = append(evs, e, dnsResp(float64(i)*30, "10.0.0.6", "ok.example.com", 0))
	}
	// ordena por tempo: o motor espera eventos em ordem cronologica aproximada
	sortByTime(evs)
	if as := run(t, Default(), evs...); len(as) != 0 {
		t.Fatalf("nao deveria alertar: %v", names(as))
	}
}

func sortByTime(evs []*psychoscopev1.EventoFluxoRede) {
	for i := 1; i < len(evs); i++ {
		for j := i; j > 0 && evs[j].TimestampCaptura.AsTime().Before(evs[j-1].TimestampCaptura.AsTime()); j-- {
			evs[j], evs[j-1] = evs[j-1], evs[j]
		}
	}
}

func TestBeaconGapResetsSeriesAndCooldown(t *testing.T) {
	var evs []*psychoscopev1.EventoFluxoRede
	// 8 batidas -> alerta; continua por mais 30 min (cooldown suprime); apos 31 min a serie
	// regular continua e alerta de novo.
	for i := 0; i < 80; i++ {
		evs = append(evs, synFrom(float64(i)*30, "10.0.0.5", "203.0.113.7", uint32(50000+i), 443))
	}
	as := run(t, Default(), evs...)
	if len(as) != 2 {
		t.Fatalf("esperado alerta inicial + um apos o cooldown de 30 min: %d", len(as))
	}

	// pausa longa (1 h > 3x intervalo) reinicia a serie: 5 + 5 batidas nao somam 8
	var gap []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 5; i++ {
		gap = append(gap, synFrom(float64(i)*30, "10.0.0.5", "203.0.113.7", uint32(50000+i), 443))
	}
	for i := 0; i < 5; i++ {
		gap = append(gap, synFrom(3600+float64(i)*30, "10.0.0.5", "203.0.113.7", uint32(51000+i), 443))
	}
	if as := run(t, Default(), gap...); len(as) != 0 {
		t.Fatalf("a serie deve reiniciar apos silencio longo: %v", names(as))
	}
}

func TestBeaconIgnoreListsAndDisabledKinds(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	cfg := Default()
	cfg.Beacon.IgnorePorts = []int{123}
	cfg.Beacon.IgnoreDomains = []string{"windowsupdate.com", "ntp.org."}
	if as := run(t, cfg, beatsTCP("10.0.0.5", "10.0.0.123", 123, 0, 30, 1, 12, rng)...); len(as) != 0 {
		t.Error("porta ignorada")
	}
	for _, d := range []string{"windowsupdate.com", "download.windowsupdate.com", "pool.NTP.org"} {
		var evs []*psychoscopev1.EventoFluxoRede
		for i := 0; i < 12; i++ {
			evs = append(evs, dnsQuery(float64(i)*30, "10.0.0.5", d))
		}
		if as := run(t, cfg, evs...); len(as) != 0 {
			t.Errorf("dominio ignorado %s", d)
		}
	}
	var evs []*psychoscopev1.EventoFluxoRede
	for i := 0; i < 12; i++ { // "notwindowsupdate.com" NAO casa com o sufixo ".windowsupdate.com"
		evs = append(evs, dnsQuery(float64(i)*30, "10.0.0.5", "notwindowsupdate.com"))
	}
	if as := run(t, cfg, evs...); len(as) != 1 {
		t.Error("sufixo deve casar so em fronteira de rotulo")
	}
}

func TestBeaconBoundedMemory(t *testing.T) {
	cfg := Default().Beacon
	cfg.MaxKeys = 100
	b := NewBeacon(cfg)
	w := detection.NewWindow(time.Minute, 1000)
	for i := 0; i < 5000; i++ { // 5000 alvos distintos, um contato cada
		ev := detection.NewEvent("m", synFrom(float64(i), "10.0.0.5", fmt.Sprintf("10.9.%d.%d", i/250, i%250), 50000, 443), time.Now())
		w.Add(ev)
		b.Eval(ev, w)
	}
	if len(b.series) > cfg.MaxKeys {
		t.Fatalf("series acima do teto: %d", len(b.series))
	}
	// ainda detecta um beacon real depois do despejo
	var got bool
	for i := 0; i < 12; i++ {
		ev := detection.NewEvent("m", synFrom(6000+float64(i)*30, "10.0.0.6", "203.0.113.9", uint32(50000+i), 443), time.Now())
		got = b.Eval(ev, w) != nil || got
	}
	if !got {
		t.Fatal("beacon real deveria ser detectado apos despejos")
	}
}

func TestIntervalStats(t *testing.T) {
	base := time.Unix(0, 0)
	ts := func(offs ...float64) []time.Time {
		var o []time.Time
		for _, x := range offs {
			o = append(o, base.Add(time.Duration(x*float64(time.Second))))
		}
		return o
	}
	if m, cv := intervalStats(ts(0, 10, 20, 30)); m != 10*time.Second || cv != 0 {
		t.Errorf("regular: %v %v", m, cv)
	}
	if m, cv := intervalStats(ts(0, 5, 20)); m != 10*time.Second || cv < 0.49 || cv > 0.51 {
		t.Errorf("(5,15): media 10s, cv 0.5: %v %v", m, cv)
	}
	if _, cv := intervalStats(ts(0)); cv < 1e9 {
		t.Errorf("serie de 1 ponto: cv deve ser infinito: %v", cv)
	}
}

func TestNewRulesConfigValidation(t *testing.T) {
	mut := map[string]func(*Config){
		"beacon min_samples baixo":         func(c *Config) { c.Beacon.MinSamples = 3 },
		"beacon min_samples acima do anel": func(c *Config) { c.Beacon.MinSamples = 33 },
		"beacon intervalos invertidos":     func(c *Config) { c.Beacon.MaxInterval = c.Beacon.MinInterval },
		"beacon cv zero":                   func(c *Config) { c.Beacon.MaxCV = 0 },
		"beacon cv > 1":                    func(c *Config) { c.Beacon.MaxCV = 1.5 },
		"beacon max_keys baixo":            func(c *Config) { c.Beacon.MaxKeys = 10 },
		"beacon porta invalida":            func(c *Config) { c.Beacon.IgnorePorts = []int{70000} },
		"bruteforce sem portas":            func(c *Config) { c.BruteForce.Ports = nil },
		"bruteforce porta invalida":        func(c *Config) { c.BruteForce.Ports = []int{0} },
		"bruteforce fonte invalida":        func(c *Config) { c.BruteForce.IgnoreSources = []string{"nao-e-ip"} },
		"icmp hosts zero":                  func(c *Config) { c.ICMPSweep.MinHosts = 0 },
		"dns rate zero":                    func(c *Config) { c.DNSRate.MinQueries = 0 },
		"tls cooldown zero":                func(c *Config) { c.TLS.Cooldown = 0 },
	}
	for name, f := range mut {
		c := Default()
		f(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: esperado erro", name)
		}
	}
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	if got := len(AllNames()); got != 8 {
		t.Errorf("AllNames: %d", got)
	}
	rs, err := Build(Default())
	if err != nil || len(rs) != 8 {
		t.Fatalf("Build: %d %v", len(rs), err)
	}
	if w := Default().LongestWindow(); w != time.Minute {
		t.Errorf("LongestWindow: %v", w)
	}
}

func durNear(t *testing.T, s string, want, tol time.Duration) bool {
	t.Helper()
	d, err := time.ParseDuration(s)
	return err == nil && d > want-tol && d < want+tol
}
