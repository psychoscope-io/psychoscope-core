// Package rules agrupa as regras analiticas do Core (detection.Rule).
package rules

import (
	"fmt"
	"slices"
	"time"

	"github.com/Bandeira27/psychoscope-core/internal/detection"
)

// Nomes das regras (usados em alertas, em Config.Disabled e no cooldown).
const (
	NameScanSYN     = "net.scan.syn"
	NameDNSNXDomain = "net.dns.nxdomain_burst"
	NameDNSTunnel   = "net.dns.tunnel"
)

// ScanConfig parametriza net.scan.syn.
type ScanConfig struct {
	Window          time.Duration // janela de observacao
	VerticalPorts   int           // portas distintas num mesmo destino => varredura vertical
	HorizontalHosts int           // destinos distintos na mesma porta => varredura horizontal
	Cooldown        time.Duration
	MaxScan         int // maximo de eventos da origem examinados por avaliacao
}

// NXDomainConfig parametriza net.dns.nxdomain_burst.
type NXDomainConfig struct {
	Window       time.Duration
	MinResponses int // respostas NXDOMAIN ao mesmo cliente
	MinDistinct  int // dominios distintos entre elas
	Cooldown     time.Duration
}

// TunnelConfig parametriza net.dns.tunnel.
type TunnelConfig struct {
	Window       time.Duration
	MinQueries   int     // consultas suspeitas distintas ao mesmo dominio base
	MinLabelLen  int     // rotulo (subdominio) com pelo menos este tamanho e suspeito...
	MinEntropy   float64 // ...se a entropia de Shannon (bits/caractere) for ao menos esta
	AllowedBases []string
	Cooldown     time.Duration
}

// Config reune os limiares de todas as regras.
type Config struct {
	Disabled []string
	Scan     ScanConfig
	NXDomain NXDomainConfig
	Tunnel   TunnelConfig
}

// Default devolve limiares conservadores.
func Default() Config {
	return Config{
		Scan:     ScanConfig{Window: 10 * time.Second, VerticalPorts: 15, HorizontalHosts: 20, Cooldown: time.Minute, MaxScan: 5000},
		NXDomain: NXDomainConfig{Window: 30 * time.Second, MinResponses: 10, MinDistinct: 8, Cooldown: 2 * time.Minute},
		Tunnel:   TunnelConfig{Window: time.Minute, MinQueries: 5, MinLabelLen: 30, MinEntropy: 3.2, Cooldown: 2 * time.Minute},
	}
}

// Validate verifica a coerencia dos limiares e dos nomes desabilitados.
func (c Config) Validate() error {
	for _, d := range c.Disabled {
		if !slices.Contains(AllNames(), d) {
			return fmt.Errorf("regra desconhecida em disabled: %q (validas: %v)", d, AllNames())
		}
	}
	pos := map[string]bool{
		"scan.window": c.Scan.Window > 0, "scan.vertical_ports": c.Scan.VerticalPorts > 0,
		"scan.horizontal_hosts": c.Scan.HorizontalHosts > 0, "scan.cooldown": c.Scan.Cooldown > 0, "scan.max_scan": c.Scan.MaxScan > 0,
		"nxdomain.window": c.NXDomain.Window > 0, "nxdomain.min_responses": c.NXDomain.MinResponses > 0,
		"nxdomain.min_distinct": c.NXDomain.MinDistinct > 0, "nxdomain.cooldown": c.NXDomain.Cooldown > 0,
		"tunnel.window": c.Tunnel.Window > 0, "tunnel.min_queries": c.Tunnel.MinQueries > 0,
		"tunnel.min_label_len": c.Tunnel.MinLabelLen > 0, "tunnel.min_entropy": c.Tunnel.MinEntropy > 0, "tunnel.cooldown": c.Tunnel.Cooldown > 0,
	}
	for k, ok := range pos {
		if !ok {
			return fmt.Errorf("detection.%s deve ser positivo", k)
		}
	}
	return nil
}

// AllNames lista as regras disponiveis.
func AllNames() []string { return []string{NameScanSYN, NameDNSNXDomain, NameDNSTunnel} }

// Build instancia as regras habilitadas.
func Build(c Config) ([]detection.Rule, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	all := []detection.Rule{NewScanSYN(c.Scan), NewNXDomainBurst(c.NXDomain), NewDNSTunnel(c.Tunnel)}
	var out []detection.Rule
	for _, r := range all {
		if !slices.Contains(c.Disabled, r.Name()) {
			out = append(out, r)
		}
	}
	return out, nil
}
