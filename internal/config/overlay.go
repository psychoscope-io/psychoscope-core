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
	t := v.Type()

	fields := map[string]int{}
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			fields[tag] = i
		}
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%s: esperado um objeto JSON: %w", path, err)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		idx, ok := fields[k]
		if !ok {
			valid := make([]string, 0, len(fields))
			for name := range fields {
				valid = append(valid, name)
			}
			sort.Strings(valid)
			return fmt.Errorf("%s: campo desconhecido %q (validos: %s)", path, k, strings.Join(valid, ", "))
		}
		f := v.Field(idx)
		if f.Type() == durationType {
			var s string
			if err := json.Unmarshal(obj[k], &s); err != nil {
				return fmt.Errorf("%s.%s: esperado texto de duracao (ex.: \"10s\")", path, k)
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("%s.%s: duracao invalida %q: %w", path, k, s, err)
			}
			f.SetInt(int64(d))
			continue
		}
		if err := json.Unmarshal(obj[k], f.Addr().Interface()); err != nil {
			return fmt.Errorf("%s.%s: %w", path, k, err)
		}
	}
	return nil
}
