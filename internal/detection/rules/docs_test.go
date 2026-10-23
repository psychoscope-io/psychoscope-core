package rules

import (
	"reflect"
	"strings"
	"testing"
)

// Todo campo de configuracao de regra precisa de nome (json) e descricao (doc): a tela de
// configuracoes mostra a descricao, entao uma regra nova nao pode nascer sem ela.
func TestEveryRuleConfigFieldIsDocumented(t *testing.T) {
	c := Default()
	sections := c.Sections()
	if len(sections) != len(AllNames()) {
		t.Fatalf("%d secoes para %d regras", len(sections), len(AllNames()))
	}
	for name, ptr := range sections {
		st := reflect.TypeOf(ptr).Elem()
		for i := 0; i < st.NumField(); i++ {
			f := st.Field(i)
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			if key == "" || key == "-" {
				t.Errorf("%s.%s sem tag json", name, f.Name)
				continue
			}
			if doc := f.Tag.Get("doc"); strings.TrimSpace(doc) == "" || !strings.HasSuffix(doc, ".") {
				t.Errorf("detection.%s.%s sem tag doc terminada em ponto: %q", name, key, doc)
			}
		}
	}
}
