package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Chaves e caminhos dos campos de detection que nao sao de uma regra.
const (
	keyWindow   = "window"
	keyDisabled = "disabled"

	PathDetectionWindow   = "detection." + keyWindow
	PathDetectionDisabled = "detection." + keyDisabled
)

// StorageField e um campo editavel de storage: a chave no arquivo, a descricao mostrada na
// tela e como alcanca o valor.
type StorageField struct {
	Key string
	Doc string
	Ptr func(*Storage) *int
}

// EditableStorage e a unica lista dos campos de storage editaveis em tempo de execucao: o
// Layer os aplica e o catalogo de internal/settings os descreve a partir dela. Campo novo =
// uma linha aqui. storage.path e storage.enabled ficam de fora de proposito.
var EditableStorage = []StorageField{
	{"retention_days", "Dias de retenção dos alertas persistidos (0 = sem limite por idade).", func(s *Storage) *int { return &s.RetentionDays }},
	{"max_alerts", "Máximo de alertas persistidos (0 = sem teto).", func(s *Storage) *int { return &s.MaxAlerts }},
}

// maxOverridesSize limita o arquivo de ajustes (entrada nao confiavel: vem do disco).
const maxOverridesSize = 1 << 20

// Overrides sao os ajustes de configuracao feitos pelo canal de controle: caminho do campo
// (detection.beacon.ignore_ports, storage.max_alerts) para o valor em JSON. Ficam num
// arquivo proprio, no diretorio de estado, sobreposto ao arquivo do administrador. So
// existe o que e editavel por ali: detection.* (menos queue_size e max_events, que exigem
// reinicio) e storage.retention_days e storage.max_alerts. Qualquer outro campo (modules,
// sockets, caminhos) e erro na leitura e na sobreposicao, de modo que o arquivo nao consegue
// carregar nada alem disso.
type Overrides map[string]json.RawMessage

// fileOverrides e o formato do arquivo: o mesmo aninhamento do arquivo principal.
type fileOverrides struct {
	Detection map[string]json.RawMessage `json:"detection"`
	Storage   map[string]json.RawMessage `json:"storage"`
}

// ReadOverrides le o arquivo de ajustes. Arquivo ausente significa sem ajustes.
func ReadOverrides(path string) (Overrides, error) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Overrides{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ajustes %s: %w", path, err)
	}
	if st.Size() > maxOverridesSize {
		return nil, fmt.Errorf("ajustes %s: arquivo grande demais (%d bytes; maximo %d); remova-o ou corrija-o", path, st.Size(), maxOverridesSize)
	}
	data, err := os.ReadFile(path) //nolint:gosec // caminho no diretorio de estado do proprio Core
	if err != nil {
		return nil, fmt.Errorf("ajustes %s: %w", path, err)
	}
	o, err := ParseOverrides(data)
	if err != nil {
		return nil, fmt.Errorf("ajustes %s: %w (corrija ou remova o arquivo para voltar a configuracao do administrador)", path, err)
	}
	return o, nil
}

// ParseOverrides interpreta o JSON aninhado do arquivo de ajustes e o achata em caminhos.
func ParseOverrides(data []byte) (Overrides, error) {
	var f fileOverrides
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	o := Overrides{}
	for k, v := range f.Storage {
		o["storage."+k] = v
	}
	for k, v := range f.Detection {
		if !isObject(v) { // window, disabled (ou campo invalido, recusado em Layer)
			o["detection."+k] = v
			continue
		}
		var sec map[string]json.RawMessage
		if err := json.Unmarshal(v, &sec); err != nil {
			return nil, fmt.Errorf("detection.%s: %w", k, err)
		}
		for fk, fv := range sec {
			o["detection."+k+"."+fk] = fv
		}
	}
	return o, nil
}

func isObject(v json.RawMessage) bool {
	return len(bytes.TrimSpace(v)) > 0 && bytes.TrimSpace(v)[0] == '{'
}

// JSON serializa no formato aninhado do arquivo, com chaves ordenadas (saida deterministica).
func (o Overrides) JSON() ([]byte, error) {
	det, sto := map[string]any{}, map[string]json.RawMessage{}
	for _, path := range o.paths() {
		top, section, key, ok := pathParts(path)
		switch {
		case !ok || (top != "storage" && top != "detection"):
			return nil, fmt.Errorf("caminho de ajuste invalido: %q", path)
		case top == "storage" && section == "":
			sto[key] = o[path]
		case top == "storage":
			return nil, fmt.Errorf("caminho de ajuste invalido: %q", path)
		case section == "":
			det[key] = o[path]
		default:
			sec, _ := det[section].(map[string]json.RawMessage)
			if sec == nil {
				sec = map[string]json.RawMessage{}
				det[section] = sec
			}
			sec[key] = o[path]
		}
	}
	out := map[string]any{}
	if len(det) > 0 {
		out["detection"] = det
	}
	if len(sto) > 0 {
		out["storage"] = sto
	}
	return json.MarshalIndent(out, "", "  ") // json ordena as chaves de mapas
}

// pathParts divide um caminho de ajuste: "storage.max_alerts" -> (storage, "", max_alerts) e
// "detection.beacon.ignore_ports" -> (detection, beacon, ignore_ports). ok e falso para outro
// numero de partes.
func pathParts(path string) (top, section, key string, ok bool) {
	p := strings.Split(path, ".")
	switch len(p) {
	case 2:
		return p[0], "", p[1], true
	case 3:
		return p[0], p[1], p[2], true
	}
	return "", "", "", false
}

func (o Overrides) paths() []string {
	ps := make([]string, 0, len(o))
	for p := range o {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return ps
}

// Layer devolve uma copia de base com os ajustes aplicados, ja validada. base nao e alterada.
// Campo fora do conjunto editavel, tipo errado ou valor invalido e erro citando o caminho.
func Layer(base *Config, o Overrides) (*Config, error) {
	c := *base
	det := fileDetection{raw: map[string]json.RawMessage{}}
	secs := map[string]map[string]json.RawMessage{}
	for _, path := range o.paths() {
		top, section, key, ok := pathParts(path)
		isScalar := section == "" && (key == keyWindow || key == keyDisabled)
		switch {
		case ok && top == "storage" && section == "":
			if err := c.applyStorageOverride(key, o[path]); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		case ok && top == "detection" && isScalar:
			det.raw[key] = o[path]
		case ok && top == "detection" && section != "" && section != keyWindow && section != keyDisabled:
			if secs[section] == nil {
				secs[section] = map[string]json.RawMessage{}
			}
			secs[section][key] = o[path]
		default:
			return nil, fmt.Errorf("ajuste nao editavel pelo canal de controle: %q (edite o arquivo de configuracao)", path)
		}
	}
	for name, sec := range secs {
		raw, err := json.Marshal(sec)
		if err != nil {
			return nil, err
		}
		det.raw[name] = raw
	}
	d, err := applyDetection(c.Detection, det)
	if err != nil {
		return nil, err
	}
	c.Detection = d
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// applyStorageOverride aplica retention_days ou max_alerts; os demais campos de storage
// (path, enabled) nao sao editaveis por ajuste.
func (c *Config) applyStorageOverride(key string, raw json.RawMessage) error {
	for _, f := range EditableStorage {
		if f.Key != key {
			continue
		}
		var v int
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("esperado um inteiro: %w", err)
		}
		*f.Ptr(&c.Storage) = v
		return nil
	}
	return fmt.Errorf("ajuste nao editavel pelo canal de controle: storage.%s (edite o arquivo de configuracao)", key)
}
