package rules

import (
	"net"
	"strings"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Campos de configuracao (caminhos como no catalogo) que guardam as excecoes de cada regra.
const (
	FieldBeaconIgnoreDestinations = "detection.beacon.ignore_destinations"
	FieldBeaconIgnoreDomains      = "detection.beacon.ignore_domains"
	FieldBruteForceIgnoreSources  = "detection.bruteforce.ignore_sources"
	FieldTunnelAllowedBases       = "detection.tunnel.allowed_bases"
)

// Exception diz qual campo de configuracao, e qual valor a acrescentar a ele, faz a regra
// deixar de disparar para o que causou este alerta (um aplicativo conhecido, um destino
// confiavel). Le so o contexto do proprio alerta. ok e falso quando a regra nao tem uma
// lista de excecoes que cubra o alerta (varredura, por exemplo, nao tem) ou o contexto nao
// traz o que e preciso.
func Exception(a *psychoscopev1.Alerta) (field, value string, ok bool) {
	ctx := a.GetContexto()
	switch a.GetRegra() {
	case NameBeacon:
		alvo := ctx["alvo"]
		switch ctx["tipo"] {
		case "tcp": // alvo = ip:porta; o IPv6 tem varios ":", o da porta e o ultimo
			i := strings.LastIndex(alvo, ":")
			if i <= 0 {
				return "", "", false
			}
			ip := alvo[:i]
			if net.ParseIP(ip) == nil {
				return "", "", false
			}
			return FieldBeaconIgnoreDestinations, ip, true
		case "dns":
			if alvo != "" {
				return FieldBeaconIgnoreDomains, alvo, true
			}
		}
	case NameBruteForce:
		if src := ctx["origem"]; net.ParseIP(src) != nil {
			return FieldBruteForceIgnoreSources, src, true
		}
	case NameDNSTunnel:
		if base := ctx["dominio_base"]; base != "" {
			return FieldTunnelAllowedBases, base, true
		}
	}
	return "", "", false
}
