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
	FieldTLSAllowedBases          = "detection.tls.allowed_bases"
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
	case NameTLSSuspicious:
		// So o motivo de entropia tem excecao por nome. O valor e o SNI sem o primeiro rotulo (o
		// aleatorio, como o hash por sessao do online-metrix.net): cobre os irmaos e nao libera
		// o dominio base inteiro. Numa plataforma compartilhada (blob.core.windows.net) isso cobre
		// outros inquilinos, e e a pessoa que confirma o valor antes de aplicar.
		if sni := ctx["sni"]; ctx["motivo"] == tlsEntropy && sni != "" {
			return FieldTLSAllowedBases, parentName(sni), true
		}
	}
	return "", "", false
}

// parentName tira o primeiro rotulo do nome; um nome de dois rotulos ou menos volta inteiro.
func parentName(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if i := strings.Index(name, "."); i >= 0 && strings.Count(name, ".") >= 2 {
		return name[i+1:]
	}
	return name
}

// Covers diz se a lista de excecoes items do campo field ja faz a regra ignorar value, e qual
// item o faz: o proprio valor ou um que o abrange (uma rede CIDR que contem o IP, um dominio
// de que value e subdominio). Usa a mesma comparacao da regra: IPs e CIDRs nas listas de
// destino e origem, nome exato ou sufixo em ignore_domains, nome exato nas demais.
func Covers(field string, items []string, value string) (item string, ok bool) {
	for _, it := range items {
		if it == value {
			return it, true
		}
	}
	for _, it := range items {
		switch field {
		case FieldBeaconIgnoreDestinations, FieldBruteForceIgnoreSources:
			if nets, err := parseSources([]string{it}); err == nil && containsIP(nets, value) {
				return it, true
			}
		case FieldBeaconIgnoreDomains, FieldTLSAllowedBases:
			if hasDomainSuffix(value, normalizeDomains([]string{it})) {
				return it, true
			}
		}
	}
	return "", false
}
