package ctl

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Conversao entre o texto que a pessoa digita (CLI e TUI) e o JSON do contrato. A validacao
// definitiva e do Core; aqui so se garante que o texto tem o formato do tipo do campo, para
// o erro aparecer na hora e sem ir ao Core.

// ValueFromText converte o texto digitado em JSON conforme o tipo do campo: numeros como
// estao, duracoes como "30s" (entre aspas no JSON) e listas separadas por virgula (ou um
// array JSON, que tambem e aceito). Lista vazia e "" ou "[]".
func ValueFromText(f *psychoscopev1.CampoConfig, text string) (string, error) {
	text = strings.TrimSpace(text)
	switch f.GetTipo() {
	case psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO:
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return "", fmt.Errorf("%s: esperado um numero inteiro, veio %q", f.Caminho, text)
		}
		return strconv.FormatInt(n, 10), nil
	case psychoscopev1.TipoCampo_TIPO_CAMPO_DECIMAL:
		v, err := strconv.ParseFloat(text, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return "", fmt.Errorf("%s: esperado um numero (por exemplo 0.2), veio %q", f.Caminho, text)
		}
		return strconv.FormatFloat(v, 'g', -1, 64), nil
	case psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO:
		if _, err := time.ParseDuration(text); err != nil {
			return "", fmt.Errorf("%s: esperada uma duracao (por exemplo 30s, 2m, 1h), veio %q", f.Caminho, text)
		}
		b, _ := json.Marshal(text)
		return string(b), nil
	case psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO:
		items, err := splitList(f, text)
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(items)
		return string(b), nil
	case psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO:
		items, err := splitList(f, text)
		if err != nil {
			return "", err
		}
		nums := make([]int64, 0, len(items))
		for _, it := range items {
			n, err := strconv.ParseInt(it, 10, 64)
			if err != nil {
				return "", fmt.Errorf("%s: esperados numeros inteiros separados por virgula, veio %q", f.Caminho, it)
			}
			nums = append(nums, n)
		}
		b, _ := json.Marshal(nums)
		return string(b), nil
	}
	return "", fmt.Errorf("%s: tipo de campo desconhecido", f.Caminho)
}

// splitList aceita "a, b" ou um array JSON ["a","b"]; itens vazios sao descartados.
func splitList(f *psychoscopev1.CampoConfig, text string) ([]string, error) {
	items := []string{}
	if strings.HasPrefix(text, "[") {
		var raw []any
		if err := json.Unmarshal([]byte(text), &raw); err != nil {
			return nil, fmt.Errorf("%s: array JSON invalido: %w", f.Caminho, err)
		}
		for _, v := range raw {
			items = append(items, strings.TrimSpace(fmt.Sprint(v)))
		}
	} else {
		items = strings.Split(text, ",")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it = strings.TrimSpace(it); it != "" {
			out = append(out, it)
		}
	}
	return out, nil
}

// TextFromValue mostra um valor JSON do contrato como o texto que se digitaria: duracoes sem
// aspas e listas separadas por virgula (lista vazia vira texto vazio).
func TextFromValue(f *psychoscopev1.CampoConfig, value string) string {
	switch f.GetTipo() {
	case psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO:
		var s string
		if json.Unmarshal([]byte(value), &s) == nil {
			return s
		}
	case psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO, psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO:
		var raw []any
		if json.Unmarshal([]byte(value), &raw) == nil {
			parts := make([]string, len(raw))
			for i, v := range raw {
				parts[i] = fmt.Sprint(v)
			}
			return strings.Join(parts, ", ")
		}
	}
	return value
}

// DisplayValue mostra um valor JSON do contrato como se digitaria; lista vazia aparece como
// (vazia) para nao sumir numa tabela.
func DisplayValue(f *psychoscopev1.CampoConfig, value string) string {
	if t := TextFromValue(f, value); t != "" {
		return t
	}
	return "(vazia)"
}

// OriginLabel e o nome, em portugues, da origem do valor de um campo.
func OriginLabel(o psychoscopev1.OrigemCampo) string {
	switch o {
	case psychoscopev1.OrigemCampo_ORIGEM_CAMPO_PADRAO:
		return "padrão"
	case psychoscopev1.OrigemCampo_ORIGEM_CAMPO_ARQUIVO:
		return "arquivo"
	case psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE:
		return "ajuste"
	}
	return "?"
}

// FindField devolve o campo de caminho path, ou nil.
func FindField(l *psychoscopev1.ListaConfig, path string) *psychoscopev1.CampoConfig {
	for _, f := range l.GetCampos() {
		if f.Caminho == path {
			return f
		}
	}
	return nil
}
