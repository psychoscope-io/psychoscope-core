// Package rules agrupa as regras analiticas do Core (detection.Rule).
package rules

import (
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
)

// Nomes das regras (usados em alertas, em Config.Disabled e no cooldown).
const (
	NameScanSYN       = "net.scan.syn"
	NameDNSNXDomain   = "net.dns.nxdomain_burst"
	NameDNSTunnel     = "net.dns.tunnel"
	NameDNSRate       = "net.dns.rate"
	NameTLSSuspicious = "net.tls.suspicious"
	NameBeacon        = "net.beacon"
	NameBruteForce    = "net.bruteforce.auth"
	NameICMPSweep     = "net.icmp.sweep"
)

// As tags `json` definem as chaves aceitas na secao "detection" do arquivo de configuracao
// (campos time.Duration viram texto: "10s", "2m").

// ScanConfig parametriza net.scan.syn.
type ScanConfig struct {
	Window          time.Duration `json:"window"`           // janela de observacao
	VerticalPorts   int           `json:"vertical_ports"`   // portas distintas num mesmo destino => varredura vertical
	HorizontalHosts int           `json:"horizontal_hosts"` // destinos distintos na mesma porta => varredura horizontal
	Cooldown        time.Duration `json:"cooldown"`
	MaxScan         int           `json:"max_scan"` // maximo de eventos da origem examinados por avaliacao
}

// NXDomainConfig parametriza net.dns.nxdomain_burst.
type NXDomainConfig struct {
	Window       time.Duration `json:"window"`
	MinResponses int           `json:"min_responses"` // respostas NXDOMAIN ao mesmo cliente
	MinDistinct  int           `json:"min_distinct"`  // dominios distintos entre elas
	Cooldown     time.Duration `json:"cooldown"`
}

// TunnelConfig parametriza net.dns.tunnel.
type TunnelConfig struct {
	Window       time.Duration `json:"window"`
	MinQueries   int           `json:"min_queries"`   // consultas suspeitas distintas ao mesmo dominio base
	MinLabelLen  int           `json:"min_label_len"` // rotulo (subdominio) com pelo menos este tamanho e suspeito...
	MinEntropy   float64       `json:"min_entropy"`   // ...se a entropia de Shannon (bits/caractere) for ao menos esta
	AllowedBases []string      `json:"allowed_bases"`
	Cooldown     time.Duration `json:"cooldown"`
}

// DNSRateConfig parametriza net.dns.rate (pico de consultas DNS por cliente).
type DNSRateConfig struct {
	Window     time.Duration `json:"window"`
	MinQueries int           `json:"min_queries"`
	Cooldown   time.Duration `json:"cooldown"`
}

// TLSConfig parametriza net.tls.suspicious.
type TLSConfig struct {
	Cooldown         time.Duration `json:"cooldown"` // por (cliente, motivo)
	MissingSNIMin    int           `json:"missing_sni_min"`
	MissingSNIWindow time.Duration `json:"missing_sni_window"`
	MinLabelLen      int           `json:"min_label_len"` // rotulo do SNI longo e de alta entropia (DGA sobre HTTPS)
	MinEntropy       float64       `json:"min_entropy"`
	AllowedBases     []string      `json:"allowed_bases"` // dominios base isentos da checagem de entropia
}

// BeaconConfig parametriza net.beacon. A regra mantem estado proprio (nao depende da
// janela deslizante, que e curta demais para beacons de minutos).
type BeaconConfig struct {
	MinSamples    int           `json:"min_samples"`  // contatos regulares necessarios (4 a 32)
	MinInterval   time.Duration `json:"min_interval"` // contatos mais proximos que isto contam como um so (rajada/retransmissao)
	MaxInterval   time.Duration `json:"max_interval"`
	MaxCV         float64       `json:"max_cv"`   // coeficiente de variacao maximo (desvio/media) dos intervalos
	MaxKeys       int           `json:"max_keys"` // teto de series acompanhadas
	Cooldown      time.Duration `json:"cooldown"`
	IgnoreDomains []string      `json:"ignore_domains"` // dominio exato ou sufixo
	IgnorePorts   []int         `json:"ignore_ports"`   // portas de destino TCP
}

// BruteForceConfig parametriza net.bruteforce.auth.
type BruteForceConfig struct {
	Window        time.Duration `json:"window"`
	MinAttempts   int           `json:"min_attempts"` // conexoes (portas de origem distintas) ao mesmo destino:porta
	Ports         []int         `json:"ports"`        // portas de autenticacao
	Cooldown      time.Duration `json:"cooldown"`
	IgnoreSources []string      `json:"ignore_sources"` // IPs ou CIDRs isentos (scanners internos, automacao)
}

// ICMPSweepConfig parametriza net.icmp.sweep.
type ICMPSweepConfig struct {
	Window   time.Duration `json:"window"`
	MinHosts int           `json:"min_hosts"`
	Cooldown time.Duration `json:"cooldown"`
}

// Config reune os limiares de todas as regras.
type Config struct {
	Disabled   []string
	Scan       ScanConfig
	NXDomain   NXDomainConfig
	Tunnel     TunnelConfig
	DNSRate    DNSRateConfig
	TLS        TLSConfig
	Beacon     BeaconConfig
	BruteForce BruteForceConfig
	ICMPSweep  ICMPSweepConfig
}

// Default devolve limiares conservadores.
func Default() Config {
	return Config{
		Scan:     ScanConfig{Window: 10 * time.Second, VerticalPorts: 15, HorizontalHosts: 20, Cooldown: time.Minute, MaxScan: 5000},
		NXDomain: NXDomainConfig{Window: 30 * time.Second, MinResponses: 10, MinDistinct: 8, Cooldown: 2 * time.Minute},
		Tunnel:   TunnelConfig{Window: time.Minute, MinQueries: 5, MinLabelLen: 30, MinEntropy: 3.2, Cooldown: 2 * time.Minute},
		DNSRate:  DNSRateConfig{Window: 10 * time.Second, MinQueries: 200, Cooldown: 2 * time.Minute},
		TLS: TLSConfig{Cooldown: 10 * time.Minute, MissingSNIMin: 3, MissingSNIWindow: time.Minute,
			MinLabelLen: 20, MinEntropy: 3.6},
		Beacon: BeaconConfig{MinSamples: 8, MinInterval: 5 * time.Second, MaxInterval: time.Hour, MaxCV: 0.2,
			MaxKeys: 50_000, Cooldown: 30 * time.Minute},
		BruteForce: BruteForceConfig{Window: 30 * time.Second, MinAttempts: 10, Ports: []int{21, 22, 23, 445, 3389, 5900},
			Cooldown: 5 * time.Minute},
		ICMPSweep: ICMPSweepConfig{Window: 10 * time.Second, MinHosts: 20, Cooldown: time.Minute},
	}
}

// Sections mapeia o nome de cada secao do arquivo de configuracao para a struct
// correspondente (ponteiro), para que o carregador as sobreponha campo a campo.
func (c *Config) Sections() map[string]any {
	return map[string]any{
		"scan": &c.Scan, "nxdomain": &c.NXDomain, "tunnel": &c.Tunnel, "dns_rate": &c.DNSRate,
		"tls": &c.TLS, "beacon": &c.Beacon, "bruteforce": &c.BruteForce, "icmp_sweep": &c.ICMPSweep,
	}
}

// LongestWindow devolve a maior janela que as regras consultam na janela deslizante do
// motor; detection.window precisa cobri-la. (Beacon tem estado proprio e nao entra.)
func (c Config) LongestWindow() time.Duration {
	return max(c.Scan.Window, c.NXDomain.Window, c.Tunnel.Window, c.DNSRate.Window,
		c.TLS.MissingSNIWindow, c.BruteForce.Window, c.ICMPSweep.Window)
}

// Validate verifica a coerencia dos limiares e dos nomes desabilitados.
func (c Config) Validate() error {
	for _, d := range c.Disabled {
		if !slices.Contains(AllNames(), d) {
			return fmt.Errorf("regra desconhecida em disabled: %q (validas: %v)", d, AllNames())
		}
	}
	if err := c.validatePositive(); err != nil {
		return err
	}
	if err := c.Beacon.validate(); err != nil {
		return err
	}
	return c.BruteForce.validate()
}

// validatePositive exige limiares, janelas e cooldowns positivos em todas as regras.
func (c Config) validatePositive() error {
	pos := map[string]bool{
		"scan.window": c.Scan.Window > 0, "scan.vertical_ports": c.Scan.VerticalPorts > 0,
		"scan.horizontal_hosts": c.Scan.HorizontalHosts > 0, "scan.cooldown": c.Scan.Cooldown > 0, "scan.max_scan": c.Scan.MaxScan > 0,
		"nxdomain.window": c.NXDomain.Window > 0, "nxdomain.min_responses": c.NXDomain.MinResponses > 0,
		"nxdomain.min_distinct": c.NXDomain.MinDistinct > 0, "nxdomain.cooldown": c.NXDomain.Cooldown > 0,
		"tunnel.window": c.Tunnel.Window > 0, "tunnel.min_queries": c.Tunnel.MinQueries > 0,
		"tunnel.min_label_len": c.Tunnel.MinLabelLen > 0, "tunnel.min_entropy": c.Tunnel.MinEntropy > 0, "tunnel.cooldown": c.Tunnel.Cooldown > 0,
		"dns_rate.window": c.DNSRate.Window > 0, "dns_rate.min_queries": c.DNSRate.MinQueries > 0, "dns_rate.cooldown": c.DNSRate.Cooldown > 0,
		"tls.cooldown": c.TLS.Cooldown > 0, "tls.missing_sni_min": c.TLS.MissingSNIMin > 0, "tls.missing_sni_window": c.TLS.MissingSNIWindow > 0,
		"tls.min_label_len": c.TLS.MinLabelLen > 0, "tls.min_entropy": c.TLS.MinEntropy > 0,
		"beacon.min_interval": c.Beacon.MinInterval > 0, "beacon.cooldown": c.Beacon.Cooldown > 0,
		"bruteforce.window": c.BruteForce.Window > 0, "bruteforce.min_attempts": c.BruteForce.MinAttempts > 0, "bruteforce.cooldown": c.BruteForce.Cooldown > 0,
		"icmp_sweep.window": c.ICMPSweep.Window > 0, "icmp_sweep.min_hosts": c.ICMPSweep.MinHosts > 0, "icmp_sweep.cooldown": c.ICMPSweep.Cooldown > 0,
	}
	for k, ok := range pos {
		if !ok {
			return fmt.Errorf("detection.%s deve ser positivo", k)
		}
	}
	return nil
}

func (b BeaconConfig) validate() error {
	switch {
	case b.MinSamples < 4 || b.MinSamples > maxSeriesLen:
		return fmt.Errorf("detection.beacon.min_samples deve estar entre 4 e %d", maxSeriesLen)
	case b.MaxInterval <= b.MinInterval:
		return fmt.Errorf("detection.beacon.max_interval (%v) deve ser maior que min_interval (%v)", b.MaxInterval, b.MinInterval)
	case b.MaxCV <= 0 || b.MaxCV > 1:
		return fmt.Errorf("detection.beacon.max_cv deve estar em (0, 1]")
	case b.MaxKeys < 100:
		return fmt.Errorf("detection.beacon.max_keys deve ser pelo menos 100")
	}
	for _, p := range b.IgnorePorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("detection.beacon.ignore_ports: porta invalida %d", p)
		}
	}
	return nil
}

func (b BruteForceConfig) validate() error {
	if len(b.Ports) == 0 {
		return fmt.Errorf("detection.bruteforce.ports nao pode ser vazio (desabilite a regra em disabled)")
	}
	for _, p := range b.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("detection.bruteforce.ports: porta invalida %d", p)
		}
	}
	if _, err := parseSources(b.IgnoreSources); err != nil {
		return fmt.Errorf("detection.bruteforce.ignore_sources: %w", err)
	}
	return nil
}

// parseSources converte uma lista de IPs/CIDRs em redes.
func parseSources(list []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, s := range list {
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%q nao e IP nem CIDR", s)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// AllNames lista as regras disponiveis.
func AllNames() []string {
	return []string{NameScanSYN, NameDNSNXDomain, NameDNSTunnel, NameDNSRate, NameTLSSuspicious, NameBeacon, NameBruteForce, NameICMPSweep}
}

// Build instancia as regras habilitadas.
func Build(c Config) ([]detection.Rule, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	all := []detection.Rule{
		NewScanSYN(c.Scan), NewNXDomainBurst(c.NXDomain), NewDNSTunnel(c.Tunnel), NewDNSRate(c.DNSRate),
		NewTLSSuspicious(c.TLS), NewBeacon(c.Beacon), NewBruteForce(c.BruteForce), NewICMPSweep(c.ICMPSweep),
	}
	var out []detection.Rule
	for _, r := range all {
		if !slices.Contains(c.Disabled, r.Name()) {
			out = append(out, r)
		}
	}
	return out, nil
}
