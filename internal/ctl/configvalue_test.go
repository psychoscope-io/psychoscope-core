package ctl

import (
	"strings"
	"testing"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func fld(t psychoscopev1.TipoCampo) *psychoscopev1.CampoConfig {
	return &psychoscopev1.CampoConfig{Caminho: "detection.x.y", Tipo: t}
}

func TestValueFromTextByType(t *testing.T) {
	for _, tc := range []struct {
		typ  psychoscopev1.TipoCampo
		in   string
		want string
	}{
		{psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO, " 30 ", "30"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO, "-1", "-1"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DECIMAL, "0.2", "0.2"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DECIMAL, "1", "1"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO, "30s", `"30s"`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO, "1h30m", `"1h30m"`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, "a.com, b.com,,", `["a.com","b.com"]`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, `["a.com","b.com"]`, `["a.com","b.com"]`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, "", `[]`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, "[]", `[]`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, `149.154.160.0/20, 2001:67c:4e8::/48`, `["149.154.160.0/20","2001:67c:4e8::/48"]`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO, "123, 443", `[123,443]`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO, "[22,3389]", `[22,3389]`},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO, "", `[]`},
	} {
		got, err := ValueFromText(fld(tc.typ), tc.in)
		if err != nil || got != tc.want {
			t.Errorf("%v %q -> %q %v, esperado %q", tc.typ, tc.in, got, err, tc.want)
		}
	}
}

func TestValueFromTextRejectsBadInputWithAField(t *testing.T) {
	for _, tc := range []struct {
		typ psychoscopev1.TipoCampo
		in  string
	}{
		{psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO, "abc"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO, "1.5"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO, ""},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DECIMAL, "x"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DECIMAL, "NaN"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO, "dez"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO, "10"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO, "1, dois"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, "[a, b"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DESCONHECIDO, "1"},
	} {
		if _, err := ValueFromText(fld(tc.typ), tc.in); err == nil || !strings.Contains(err.Error(), "detection.x.y") {
			t.Errorf("%v %q: deveria falhar citando o campo: %v", tc.typ, tc.in, err)
		}
	}
}

func TestTextFromValueRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		typ  psychoscopev1.TipoCampo
		json string
		text string
	}{
		{psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO, "15", "15"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DECIMAL, "0.2", "0.2"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO, `"1m"`, "1m"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, `["a.com","b.com"]`, "a.com, b.com"},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, `[]`, ""},
		{psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO, `[123,443]`, "123, 443"},
	} {
		f := fld(tc.typ)
		if got := TextFromValue(f, tc.json); got != tc.text {
			t.Errorf("%v %s -> %q, esperado %q", tc.typ, tc.json, got, tc.text)
		}
		back, err := ValueFromText(f, tc.text)
		if err != nil || back != tc.json {
			t.Errorf("ida e volta de %q: %q %v, esperado %q", tc.text, back, err, tc.json)
		}
	}
}

func TestDisplayValueOriginLabelAndFindField(t *testing.T) {
	lista := fld(psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO)
	if got := DisplayValue(lista, `[]`); got != "[]" {
		t.Errorf("lista vazia nao pode sumir da tabela: %q", got)
	}
	if got := DisplayValue(lista, `["a","b"]`); got != "a, b" {
		t.Errorf("lista: %q", got)
	}
	if got := DisplayValue(fld(psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO), `"1m"`); got != "1m" {
		t.Errorf("duracao: %q", got)
	}
	for o, want := range map[psychoscopev1.OrigemCampo]string{
		psychoscopev1.OrigemCampo_ORIGEM_CAMPO_PADRAO:       "padrão",
		psychoscopev1.OrigemCampo_ORIGEM_CAMPO_ARQUIVO:      "arquivo",
		psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE:       "ajuste",
		psychoscopev1.OrigemCampo_ORIGEM_CAMPO_DESCONHECIDA: "?",
	} {
		if got := OriginLabel(o); got != want {
			t.Errorf("%v: %q, esperado %q", o, got, want)
		}
	}
	l := &psychoscopev1.ListaConfig{Campos: []*psychoscopev1.CampoConfig{{Caminho: "a.b"}, {Caminho: "c.d"}}}
	if FindField(l, "c.d") != l.Campos[1] || FindField(l, "x") != nil || FindField(nil, "a.b") != nil {
		t.Error("FindField")
	}
}
