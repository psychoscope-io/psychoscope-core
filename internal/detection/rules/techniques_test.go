package rules

import (
	"regexp"
	"slices"
	"testing"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

var techniqueID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func alertOf(rule string, ctx map[string]string) *psychoscopev1.Alerta {
	return &psychoscopev1.Alerta{Regra: rule, Contexto: ctx}
}

// Toda regra tem uma decisao explicita sobre o ATT&CK: uma tecnica (fixa ou por contexto), ou o
// motivo de nao ter; e os mapas so falam de regras que existem.
func TestEveryRuleHasAnAttackDecision(t *testing.T) {
	for _, n := range AllNames() {
		_, fixed := ruleTechniques[n]
		_, byCtx := contextTechniques[n]
		reason, none := noTechnique[n]
		decisions := 0
		for _, d := range []bool{fixed, byCtx, none} {
			if d {
				decisions++
			}
		}
		switch {
		case decisions == 0:
			t.Errorf("regra %s sem decisao ATT&CK: mapeie em ruleTechniques/contextTechniques ou justifique em noTechnique", n)
		case decisions > 1:
			t.Errorf("regra %s esta em mais de um mapa de tecnicas: escolha um", n)
		case none && reason == "":
			t.Errorf("regra %s sem motivo em noTechnique", n)
		}
		for _, tech := range possibleTechniques(n) {
			if !techniqueID.MatchString(tech.ID) || tech.Name == "" {
				t.Errorf("regra %s com tecnica malformada: %+v", n, tech)
			}
		}
	}
	for _, n := range keysOf(ruleTechniques, contextTechniques, noTechnique) {
		if !slices.Contains(AllNames(), n) {
			t.Errorf("os mapas de tecnicas tem %q, que nao e uma regra de AllNames()", n)
		}
	}
	if attackVersion == "" {
		t.Error("attackVersion deve registrar a versao do ATT&CK conferida")
	}
}

func keysOf(a map[string]Technique, b map[string]contextRule, c map[string]string) []string {
	var out []string
	for k := range a {
		out = append(out, k)
	}
	for k := range b {
		out = append(out, k)
	}
	for k := range c {
		out = append(out, k)
	}
	return out
}

func TestTechniqueOfAlert(t *testing.T) {
	tech, ok := TechniqueOf(alertOf(NameScanSYN, nil))
	if !ok || tech.String() != "T1046 Network Service Discovery" || tech.URL() != "https://attack.mitre.org/techniques/T1046/" {
		t.Errorf("T1046: %q %q %v", tech.String(), tech.URL(), ok)
	}
	sub, _ := TechniqueOf(alertOf(NameDNSTunnel, nil))
	if sub.URL() != "https://attack.mitre.org/techniques/T1071/004/" {
		t.Errorf("subtecnica deve virar T1071/004: %q", sub.URL())
	}
	for _, a := range []*psychoscopev1.Alerta{
		alertOf(NameDNSRate, nil), alertOf("outra.regra", nil),
		alertOf(NameBeacon, map[string]string{"tipo": "tcp"}), // so SYNs regulares: nao ha protocolo de aplicacao
		alertOf(NameBeacon, nil),
	} {
		if tech, ok := TechniqueOf(a); ok {
			t.Errorf("%s %v nao devia ter tecnica, veio %v", a.Regra, a.Contexto, tech)
		}
	}
	if tech, ok := TechniqueOf(alertOf(NameBeacon, map[string]string{"tipo": "dns"})); !ok || tech.ID != "T1071.004" {
		t.Errorf("beacon por DNS: %v %v", tech, ok)
	}
}
