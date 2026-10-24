package rules

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// Todo campo de configuracao de regra precisa de nome (json), nome para exibir (label) e
// descricao (doc): a tela de configuracoes mostra os dois ultimos, entao uma regra nova nao
// pode nascer sem eles.
// maxLabelRunes cabe na coluna do nome da tela de configuracoes.
const maxLabelRunes = 28

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
			if l := f.Tag.Get("label"); strings.TrimSpace(l) == "" || strings.HasSuffix(l, ".") || utf8.RuneCountInString(l) > maxLabelRunes {
				t.Errorf("detection.%s.%s precisa de tag label (ate %d caracteres, sem ponto final): %q", name, key, maxLabelRunes, l)
			}
		}
	}
}

func TestEveryRuleAndSectionHasALabel(t *testing.T) {
	for _, n := range AllNames() {
		if RuleLabel(n) == n {
			t.Errorf("regra %s sem nome legivel em ruleLabels", n)
		}
	}
	c := Default()
	for section := range c.Sections() {
		rule, ok := SectionRule(section)
		if !ok || !slices.Contains(AllNames(), rule) {
			t.Errorf("secao %q sem regra em sectionRules", section)
		}
	}
	if RuleLabel("outra.regra") != "outra.regra" || ContextLabel("chave_nova") != "chave_nova" {
		t.Error("o que nao esta na tabela volta pelo proprio identificador")
	}
	if ContextLabel("dominio_base") != "Domínio base" {
		t.Error("chave conhecida deve ter nome legivel")
	}
}
