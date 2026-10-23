// Package settings aplica ajustes de configuracao feitos em tempo de execucao (tela de
// configuracoes da TUI e CLI): descreve os campos editaveis, valida em conjunto, grava o
// arquivo de ajustes, aplica ao vivo e registra a auditoria.
package settings

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
)

// FieldType e o tipo de valor de um campo.
type FieldType int

const (
	TypeInt FieldType = iota + 1
	TypeDecimal
	TypeDuration
	TypeTextList
	TypeIntList
)

// Origin diz de onde vem o valor atual de um campo.
type Origin int

const (
	OriginDefault  Origin = iota + 1 // padrao do Core
	OriginFile                       // arquivo do administrador
	OriginOverride                   // ajuste feito pelo canal de controle
)

// Field e um campo editavel com valor atual e padrao (ambos em JSON).
type Field struct {
	Path    string
	Type    FieldType
	Value   string
	Default string
	Origin  Origin
	Doc     string
}

// entry e um campo descrito a partir de uma configuracao.
type entry struct {
	path  string
	typ   FieldType
	value string
	doc   string
}

// Documentacao dos campos de detection que nao sao de uma regra (os das regras tem a tag doc
// e os de storage vem de config.EditableStorage).
const (
	docWindow   = "Duração da janela deslizante do motor; precisa cobrir a maior janela de regra."
	docDisabled = "Regras desligadas, pelo nome (por exemplo net.beacon)."
)

var durationType = reflect.TypeOf(time.Duration(0))

// defaults e a configuracao com os padroes do Core nos campos editaveis.
func defaults() *config.Config {
	return &config.Config{
		Detection: config.DefaultDetection(),
		Storage:   config.Storage{RetentionDays: config.DefaultRetentionDays, MaxAlerts: config.DefaultMaxAlerts},
	}
}

// describe lista, em ordem estavel, todos os campos editaveis de c com os valores atuais:
// detection.window, detection.disabled, as secoes de regra em ordem alfabetica e storage.
func describe(c *config.Config) ([]entry, error) {
	var out []entry
	win, _ := json.Marshal(formatDuration(c.Detection.Window))
	out = append(out, entry{config.PathDetectionWindow, TypeDuration, string(win), docWindow})
	dis, err := marshalList(c.Detection.Rules.Disabled)
	if err != nil {
		return nil, err
	}
	out = append(out, entry{config.PathDetectionDisabled, TypeTextList, dis, docDisabled})

	rc := c.Detection.Rules // copia: Sections devolve ponteiros para ela
	sections := rc.Sections()
	names := make([]string, 0, len(sections))
	for n := range sections {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		st := reflect.ValueOf(sections[name]).Elem()
		for i := 0; i < st.NumField(); i++ {
			sf := st.Type().Field(i)
			key := strings.Split(sf.Tag.Get("json"), ",")[0]
			e, err := describeField(sf, st.Field(i))
			if err != nil {
				return nil, fmt.Errorf("detection.%s.%s: %w", name, key, err)
			}
			e.path = "detection." + name + "." + key
			e.doc = sf.Tag.Get("doc")
			out = append(out, e)
		}
	}
	st := c.Storage // copia: Ptr devolve ponteiros para ela
	for _, f := range config.EditableStorage {
		out = append(out, entry{"storage." + f.Key, TypeInt, fmt.Sprint(*f.Ptr(&st)), f.Doc})
	}
	return out, nil
}

// describeField converte um campo de struct de regra no tipo e no valor JSON do catalogo.
func describeField(sf reflect.StructField, v reflect.Value) (entry, error) {
	switch {
	case sf.Type == durationType:
		b, _ := json.Marshal(formatDuration(time.Duration(v.Int())))
		return entry{typ: TypeDuration, value: string(b)}, nil
	case v.Kind() == reflect.Int:
		return entry{typ: TypeInt, value: fmt.Sprint(v.Int())}, nil
	case v.Kind() == reflect.Float64:
		return entry{typ: TypeDecimal, value: fmt.Sprint(v.Float())}, nil
	case v.Kind() == reflect.Slice && sf.Type.Elem().Kind() == reflect.String:
		s, err := marshalList(v.Interface())
		return entry{typ: TypeTextList, value: s}, err
	case v.Kind() == reflect.Slice && sf.Type.Elem().Kind() == reflect.Int:
		s, err := marshalList(v.Interface())
		return entry{typ: TypeIntList, value: s}, err
	}
	return entry{}, fmt.Errorf("tipo %s nao suportado pelo catalogo (inclua-o em describeField)", sf.Type)
}

// marshalList serializa uma lista; lista vazia ou nula vira [] (nunca null).
func marshalList(v any) (string, error) {
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Slice && rv.Len() == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// formatDuration escreve a duracao de forma compacta: 1m em vez de 1m0s, 2h em vez de 2h0m0s.
func formatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Catalog monta os campos editaveis com valor atual (effective), padrao e origem. Um campo
// com ajuste e AJUSTE; sem ajuste, e ARQUIVO se difere do padrao e PADRAO se nao.
func Catalog(effective *config.Config, ov config.Overrides) ([]Field, error) {
	cur, err := describe(effective)
	if err != nil {
		return nil, err
	}
	def, err := describe(defaults())
	if err != nil {
		return nil, err
	}
	out := make([]Field, len(cur))
	for i, e := range cur {
		f := Field{Path: e.path, Type: e.typ, Value: e.value, Default: def[i].value, Doc: e.doc}
		switch _, overridden := ov[e.path]; {
		case overridden:
			f.Origin = OriginOverride
		case e.value != def[i].value:
			f.Origin = OriginFile
		default:
			f.Origin = OriginDefault
		}
		out[i] = f
	}
	return out, nil
}
