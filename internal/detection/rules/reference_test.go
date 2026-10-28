package rules

import (
	"os"
	"strings"
	"testing"
)

// A pagina docs/REGRAS.md precisa ter uma secao por regra, com as partes que o operador
// procura ao investigar um alerta: uma regra nova nao pode nascer sem documentacao.
func TestReferencePageCoversEveryRule(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/REGRAS.md")
	if err != nil {
		t.Fatalf("pagina de referencia ausente: %v", err)
	}
	doc := string(raw)
	if !strings.Contains(doc, "ATT&CK Enterprise "+attackVersion) {
		t.Errorf("docs/REGRAS.md deve dizer contra qual versao do ATT&CK o mapa foi conferido (%s)", attackVersion)
	}
	for _, name := range AllNames() {
		_, rest, found := strings.Cut(doc, "\n## `"+name+"`")
		if !found {
			t.Errorf("docs/REGRAS.md sem a secao da regra %s", name)
			continue
		}
		section, _, _ := strings.Cut(rest, "\n---")
		for _, part := range []string{"**O que detecta", "**Por que importa", "**Contexto do alerta", "**O que investigar", "**Falsos positivos", "**Técnica MITRE ATT&CK.**", "**Como ajustar"} {
			if !strings.Contains(section, part) {
				t.Errorf("secao de %s sem %q", name, part)
			}
		}
		// a pagina diz o mesmo que as tabelas: cada tecnica possivel (ID, nome e link) ou o motivo de nao ter
		for _, tech := range possibleTechniques(name) {
			if want := "[" + tech.String() + "](" + tech.URL() + ")"; !strings.Contains(section, want) {
				t.Errorf("secao de %s sem a tecnica %s", name, want)
			}
		}
		if reason, none := noTechnique[name]; none {
			if want := "**Técnica MITRE ATT&CK.** Sem técnica equivalente: " + reason; !strings.Contains(section, want) {
				t.Errorf("secao de %s deveria dizer %q", name, want)
			}
		}
		if _, byCtx := contextTechniques[name]; byCtx && !strings.Contains(section, "`tipo=tcp`") {
			t.Errorf("secao de %s deveria dizer o que acontece nos demais valores de tipo (`tipo=tcp`)", name)
		}
	}
}
