package config

import (
	"fmt"
	"net"
)

// Metrics configura o endpoint opcional de metricas (formato Prometheus).
type Metrics struct {
	Listen           string // "" = desligado; ex.: 127.0.0.1:9464
	AllowNonLoopback bool
}

type fileMetrics struct {
	Listen           string `json:"listen"`
	AllowNonLoopback bool   `json:"allow_non_loopback"`
}

func (m Metrics) validate() error {
	if m.Listen == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(m.Listen)
	if err != nil || port == "" {
		return fmt.Errorf("metrics.listen invalido %q (use host:porta)", m.Listen)
	}
	if !m.AllowNonLoopback && !isLoopbackHost(host) {
		return fmt.Errorf("metrics.listen %q nao e loopback; o endpoint nao tem autenticacao (defina metrics.allow_non_loopback para permitir)", m.Listen)
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
