package rules

import (
	"reflect"
	"sort"
)

// ChangedRules devolve os nomes das regras cuja secao de configuracao difere entre a e b.
// O motor usa a lista para recomecar do zero so as regras que o operador ajustou.
func ChangedRules(a, b Config) []string {
	sa, sb := a.Sections(), b.Sections()
	var out []string
	for section, pa := range sa {
		if reflect.DeepEqual(pa, sb[section]) {
			continue
		}
		if name, ok := SectionRule(section); ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
