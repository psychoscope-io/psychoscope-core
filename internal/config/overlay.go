package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

var durationType = reflect.TypeOf(time.Duration(0))

// overlayStruct aplica o objeto JSON raw sobre *dst (ponteiro para struct), alterando
// somente os campos presentes. As chaves sao os nomes das tags `json`; chave desconhecida
// e erro (lista as validas); campos time.Duration aceitam strings como "10s" ou "2m".
func overlayStruct(raw json.RawMessage, dst any, path string) error {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("%s: destino invalido", path)
	}
	v = v.Elem()
	fields := jsonFields(v.Type())

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%s: esperado um objeto JSON: %w", path, err)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys) // erros deterministicos
	for _, k := range keys {
		idx, ok := fields[k]
		if !ok {
			return fmt.Errorf("%s: campo desconhecido %q (validos: %s)", path, k, strings.Join(sortedKeys(fields), ", "))
		}
		if err := setField(v.Field(idx), obj[k]); err != nil {
			return fmt.Errorf("%s.%s: %w", path, k, err)
		}
	}
	return nil
}

// jsonFields mapeia o nome da tag json de cada campo exportado para o seu indice.
func jsonFields(t reflect.Type) map[string]int {
	fields := map[string]int{}
	for i := 0; i < t.NumField(); i++ {
		if tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]; tag != "" && tag != "-" {
			fields[tag] = i
		}
	}
	return fields
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// setField decodifica raw no campo f; time.Duration vem como texto ("10s").
func setField(f reflect.Value, raw json.RawMessage) error {
	if f.Type() != durationType {
		return json.Unmarshal(raw, f.Addr().Interface())
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("esperado texto de duracao (ex.: \"10s\")")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duracao invalida %q: %w", s, err)
	}
	f.SetInt(int64(d))
	return nil
}
