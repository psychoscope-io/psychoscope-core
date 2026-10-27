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
		for _, part := range []string{"**O que detecta", "**Por que importa", "**Contexto do alerta", "**O que investigar", "**Falsos positivos", "**Como ajustar"} {
			if !strings.Contains(section, part) {
				t.Errorf("secao de %s sem %q", name, part)
			}
		}
	}
}
