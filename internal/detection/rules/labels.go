package rules

// Nomes para exibir ao usuario. Os identificadores tecnicos (nome da regra, chave do
// contexto) continuam sendo o contrato; estes textos so aparecem na interface, e o que nao
// esta na tabela aparece pelo proprio identificador.

var ruleLabels = map[string]string{
	NameScanSYN:       "Varredura de portas (SYN)",
	NameDNSNXDomain:   "Rajada de NXDOMAIN",
	NameDNSTunnel:     "Túnel DNS",
	NameDNSRate:       "Pico de consultas DNS",
	NameTLSSuspicious: "TLS suspeito",
	NameBeacon:        "Beacon (conexões periódicas)",
	NameBruteForce:    "Força bruta de autenticação",
	NameICMPSweep:     "Varredura ICMP",
}

// sectionRules liga a secao de detection.<secao> (chave de Config.Sections) a regra.
var sectionRules = map[string]string{
	"scan": NameScanSYN, "nxdomain": NameDNSNXDomain, "tunnel": NameDNSTunnel, "dns_rate": NameDNSRate,
	"tls": NameTLSSuspicious, "beacon": NameBeacon, "bruteforce": NameBruteForce, "icmp_sweep": NameICMPSweep,
}

// RuleLabel e o nome legivel de uma regra ("net.beacon" -> "Beacon (conexões periódicas)");
// uma regra desconhecida volta pelo proprio nome.
func RuleLabel(name string) string {
	if l, ok := ruleLabels[name]; ok {
		return l
	}
	return name
}

// SectionRule devolve o nome da regra da secao de detection.<secao> ("beacon" -> "net.beacon").
func SectionRule(section string) (rule string, ok bool) {
	rule, ok = sectionRules[section]
	return rule, ok
}

var contextLabels = map[string]string{
	"alvo": "Alvo", "amostras": "Amostras", "chave": "Chave", "cliente": "Cliente", "conexoes": "Conexões",
	"consulta_exemplo": "Consulta de exemplo", "consultas": "Consultas", "consultas_distintas": "Consultas distintas",
	"destino": "Destino", "dominio_base": "Domínio base", "dominios_distintos": "Domínios distintos",
	"dominios_exemplo": "Domínios de exemplo", "hosts_distintos": "Destinos distintos", "intervalo_medio": "Intervalo médio",
	"janela": "Janela", "motivo": "Motivo", "origem": "Origem", "porta": "Porta", "portas_distintas": "Portas distintas",
	"portas_exemplo": "Portas de exemplo", "resolvedor": "Resolvedor", "respostas_nxdomain": "Respostas NXDOMAIN",
	"sem_resposta": "Hosts sem resposta", "sni": "SNI", "tipo": "Tipo", "variacao_pct": "Variação (%)", "versao_tls": "Versão do TLS",
}

// ContextLabel e o nome legivel de uma chave do contexto de alerta; chave desconhecida volta
// pelo proprio nome.
func ContextLabel(key string) string {
	if l, ok := contextLabels[key]; ok {
		return l
	}
	return key
}
