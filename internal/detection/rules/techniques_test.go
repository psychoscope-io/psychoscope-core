package rules

import (
	"regexp"
	"testing"
)

var techniqueID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// Toda regra tem uma decisao explicita sobre o ATT&CK: uma tecnica, ou o motivo de nao ter.
func TestEveryRuleHasAnAttackDecision(t *testing.T) {
	for _, n := range AllNames() {
		tech, has := TechniqueOf(n)
		reason, none := noTechnique[n]
		switch {
		case has && none:
			t.Errorf("regra %s esta em ruleTechniques e em noTechnique: escolha uma", n)
		case !has && !none:
			t.Errorf("regra %s sem decisao ATT&CK: mapeie em ruleTechniques ou justifique em noTechnique", n)
		case has && (!techniqueID.MatchString(tech.ID) || tech.Name == ""):
			t.Errorf("regra %s com tecnica malformada: %+v", n, tech)
		case none && reason == "":
			t.Errorf("regra %s sem motivo em noTechnique", n)
		}
	}
	for n := range ruleTechniques {
		if RuleLabel(n) == n {
			t.Errorf("ruleTechniques tem %q, que nao e uma regra", n)
		}
	}
	for n := range noTechnique {
		if RuleLabel(n) == n {
			t.Errorf("noTechnique tem %q, que nao e uma regra", n)
		}
	}
}

func TestTechniqueFormatting(t *testing.T) {
	tech, ok := TechniqueOf(NameScanSYN)
	if !ok || tech.String() != "T1046 Network Service Discovery" || tech.URL() != "https://attack.mitre.org/techniques/T1046/" {
		t.Errorf("T1046: %q %q %v", tech.String(), tech.URL(), ok)
	}
	sub, _ := TechniqueOf(NameDNSTunnel)
	if sub.URL() != "https://attack.mitre.org/techniques/T1071/004/" {
		t.Errorf("subtecnica deve virar T1071/004: %q", sub.URL())
	}
	if _, ok := TechniqueOf(NameDNSRate); ok {
		t.Error("net.dns.rate nao tem tecnica equivalente")
	}
	if _, ok := TechniqueOf("outra.regra"); ok {
		t.Error("regra desconhecida nao tem tecnica")
	}
}
