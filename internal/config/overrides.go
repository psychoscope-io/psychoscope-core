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
		parts := strings.Split(path, ".")
		switch {
		case parts[0] == "storage" && len(parts) == 2:
			sto[parts[1]] = o[path]
		case parts[0] == "detection" && len(parts) == 2:
			det[parts[1]] = o[path]
		case parts[0] == "detection" && len(parts) == 3:
			sec, _ := det[parts[1]].(map[string]json.RawMessage)
			if sec == nil {
				sec = map[string]json.RawMessage{}
				det[parts[1]] = sec
			}
			sec[parts[2]] = o[path]
		default:
			return nil, fmt.Errorf("caminho de ajuste invalido: %q", path)
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
		parts := strings.Split(path, ".")
		switch {
		case len(parts) == 2 && parts[0] == "storage":
			if err := c.applyStorageOverride(parts[1], o[path]); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		case len(parts) == 2 && parts[0] == "detection" && (parts[1] == "window" || parts[1] == "disabled"):
			det.raw[parts[1]] = o[path]
		case len(parts) == 3 && parts[0] == "detection" && parts[1] != "window" && parts[1] != "disabled":
			if secs[parts[1]] == nil {
				secs[parts[1]] = map[string]json.RawMessage{}
			}
			secs[parts[1]][parts[2]] = o[path]
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
	var dst *int
	switch key {
	case "retention_days":
		dst = &c.Storage.RetentionDays
	case "max_alerts":
		dst = &c.Storage.MaxAlerts
	default:
		return fmt.Errorf("ajuste nao editavel pelo canal de controle: storage.%s (edite o arquivo de configuracao)", key)
	}
	var v int
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("esperado um inteiro: %w", err)
	}
	*dst = v
	return nil
}
