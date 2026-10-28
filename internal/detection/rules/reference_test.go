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
		// a pagina diz o mesmo que a tabela: a tecnica (com ID, nome e link) ou o "sem tecnica"
		if tech, ok := TechniqueOf(name); ok {
			if want := "[" + tech.String() + "](" + tech.URL() + ")"; !strings.Contains(section, want) {
				t.Errorf("secao de %s sem a tecnica %s", name, want)
			}
		} else if !strings.Contains(section, "**Técnica MITRE ATT&CK.** Sem técnica equivalente") {
			t.Errorf("secao de %s deveria dizer que nao tem tecnica equivalente", name)
		}
	}
}
