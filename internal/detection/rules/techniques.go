package rules

import "strings"

// Technique e uma tecnica do MITRE ATT&CK (https://attack.mitre.org), o vocabulario comum de
// quem enquadra um incidente. E metadado local: a regra detecta um indicio compativel com a
// tecnica, nao a confirma (o net.beacon, por exemplo, tambem dispara em keepalive legitimo).
type Technique struct {
	ID   string // "T1046" ou "T1071.004" (subtecnica)
	Name string // nome oficial do catalogo, em ingles
}

// String e a forma mostrada ao usuario: "T1046 Network Service Discovery".
func (t Technique) String() string { return t.ID + " " + t.Name }

// URL e a pagina da tecnica no catalogo ("T1071.004" -> .../techniques/T1071/004/).
func (t Technique) URL() string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(t.ID, ".", "/") + "/"
}

// ruleTechniques mapeia cada regra que tem uma tecnica equivalente (uma por regra). Regra nova
// entra aqui ou em noTechnique: um teste cobra a decisao explicita.
var ruleTechniques = map[string]Technique{
	NameScanSYN:     {"T1046", "Network Service Discovery"},
	NameICMPSweep:   {"T1018", "Remote System Discovery"},
	NameBruteForce:  {"T1110", "Brute Force"},
	NameDNSNXDomain: {"T1568.002", "Dynamic Resolution: Domain Generation Algorithms"},
	NameDNSTunnel:   {"T1071.004", "Application Layer Protocol: DNS"},
	NameBeacon:      {"T1071", "Application Layer Protocol"},
}

// noTechnique lista as regras sem tecnica equivalente e o porque: forcar um ID daria falsa
// precisao ao enquadramento.
var noTechnique = map[string]string{
	NameDNSRate:       "um pico de consultas DNS e volume, nao o comportamento de uma tecnica especifica",
	NameTLSSuspicious: "SNI com IP literal e versao antiga de TLS sao anomalias de configuracao, sem tecnica que as descreva",
}

// TechniqueOf devolve a tecnica ATT&CK compativel com a regra; false se a regra nao tem uma.
func TechniqueOf(rule string) (Technique, bool) {
	t, ok := ruleTechniques[rule]
	return t, ok
}
