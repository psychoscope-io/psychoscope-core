package rules

import (
	"sort"
	"strings"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// attackVersion e a versao do ATT&CK (Enterprise) contra a qual os IDs e nomes abaixo foram
// conferidos em attack.mitre.org, em 2026-10-28. Ao revisar o mapa, confira de novo e atualize.
const attackVersion = "v20"

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
// entra aqui, em contextTechniques ou em noTechnique: um teste cobra a decisao explicita.
var ruleTechniques = map[string]Technique{
	NameScanSYN:     {"T1046", "Network Service Discovery"},
	NameICMPSweep:   {"T1018", "Remote System Discovery"},
	NameBruteForce:  {"T1110", "Brute Force"},
	NameDNSNXDomain: {"T1568.002", "Dynamic Resolution: Domain Generation Algorithms"},
	NameDNSTunnel:   {"T1071.004", "Application Layer Protocol: DNS"},
}

// contextTechniques cobre a regra cuja tecnica depende de uma chave do contexto do alerta: o
// net.beacon por DNS e comando e controle sobre DNS, mas o por SYN so mostra conexoes regulares,
// sem protocolo de aplicacao, entao nao ganha tecnica (os valores ausentes de byValue).
var contextTechniques = map[string]contextRule{
	NameBeacon: {"tipo", map[string]Technique{"dns": {"T1071.004", "Application Layer Protocol: DNS"}}},
}

// contextRule escolhe a tecnica pelo valor de uma chave do contexto.
type contextRule struct {
	key     string
	byValue map[string]Technique
}

// noTechnique lista as regras sem tecnica equivalente e o porque, que a pagina de referencia
// repete (um teste compara): forcar um ID daria falsa precisao ao enquadramento.
var noTechnique = map[string]string{
	NameDNSRate:       "um pico de consultas DNS é volume, não o comportamento de uma técnica específica.",
	NameTLSSuspicious: "SNI com IP literal e versão antiga de TLS são anomalias de configuração, sem técnica que as descreva.",
}

// TechniqueOf devolve a tecnica ATT&CK compativel com o alerta; false se nao ha uma. Depende da
// regra e, no net.beacon, do tipo no contexto.
func TechniqueOf(a *psychoscopev1.Alerta) (Technique, bool) {
	if v, ok := contextTechniques[a.GetRegra()]; ok {
		t, ok := v.byValue[a.GetContexto()[v.key]]
		return t, ok
	}
	t, ok := ruleTechniques[a.GetRegra()]
	return t, ok
}

// possibleTechniques lista, ordenadas, todas as tecnicas que a regra pode indicar.
func possibleTechniques(rule string) []Technique {
	var out []Technique
	if t, ok := ruleTechniques[rule]; ok {
		out = append(out, t)
	}
	for _, t := range contextTechniques[rule].byValue {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
