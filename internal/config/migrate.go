package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// SensorMigration e o resultado de MigrateSensorToExternal.
type SensorMigration struct {
	Config    []byte   // configuracao reescrita (so valida se Changed)
	SensorEnv []string // linhas CHAVE=valor para o sensor.env: SENSOR_ARGS e as variaveis do antigo "env"
	Changed   bool     // havia um sensor lancado pelo Core para migrar
}

const sensorBinaryName = "mod-net-sensor"

// MigrateSensorToExternal converte, na configuracao antiga, o sensor que o Core lancava (path,
// args, env) no modulo External mantido pelo systemd (external e user). Os argumentos e o
// ambiente passam para o sensor.env, porque quem lanca o sensor agora e a unit. Todo o resto da
// configuracao, inclusive campos do proprio modulo, fica como esta. Devolve erro, sem migrar
// nada, quando a conversao nao e fiel (mais de um sensor, argumento com espaco ou aspas que o
// systemd dividiria errado, variavel de ambiente com quebra de linha): o operador migra a mao.
func MigrateSensorToExternal(raw []byte, user string) (SensorMigration, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return SensorMigration{}, fmt.Errorf("configuracao nao e um JSON valido: %w", err)
	}
	var mods []map[string]json.RawMessage
	if rm, ok := top["modules"]; ok {
		if err := json.Unmarshal(rm, &mods); err != nil {
			return SensorMigration{}, fmt.Errorf("campo modules invalido: %w", err)
		}
	}
	idx := -1
	for i, m := range mods {
		if isLaunchedSensor(m) {
			if idx >= 0 {
				return SensorMigration{}, fmt.Errorf("ha mais de um modulo %s lancado pelo Core; migre a mao (veja docs/INSTALL.md)", sensorBinaryName)
			}
			idx = i
		}
	}
	if idx < 0 {
		return SensorMigration{}, nil
	}
	envLines, err := sensorEnvLines(mods[idx])
	if err != nil {
		return SensorMigration{}, err
	}
	migrated := map[string]json.RawMessage{}
	for k, v := range mods[idx] {
		if k != "path" && k != "args" && k != "env" {
			migrated[k] = v
		}
	}
	migrated["external"] = json.RawMessage("true")
	u, _ := json.Marshal(user)
	migrated["user"] = u
	mods[idx] = migrated
	rm, err := json.Marshal(mods)
	if err != nil {
		return SensorMigration{}, err
	}
	top["modules"] = rm
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(top); err != nil {
		return SensorMigration{}, err
	}
	return SensorMigration{Config: buf.Bytes(), SensorEnv: envLines, Changed: true}, nil
}

func isLaunchedSensor(m map[string]json.RawMessage) bool {
	var path string
	var external bool
	_ = json.Unmarshal(m["path"], &path)
	_ = json.Unmarshal(m["external"], &external)
	return !external && path != "" && filepath.Base(path) == sensorBinaryName
}

func sensorEnvLines(m map[string]json.RawMessage) ([]string, error) {
	var args, env []string
	if a, ok := m["args"]; ok {
		if err := json.Unmarshal(a, &args); err != nil {
			return nil, fmt.Errorf("args do sensor invalidos: %w", err)
		}
	}
	if e, ok := m["env"]; ok {
		if err := json.Unmarshal(e, &env); err != nil {
			return nil, fmt.Errorf("env do sensor invalido: %w", err)
		}
	}
	var lines []string
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\r\n\"'\\$%") {
			return nil, fmt.Errorf("o argumento %q do sensor tem espaco, aspas ou caractere especial que o systemd dividiria errado; coloque-o a mao em SENSOR_ARGS no sensor.env", a)
		}
	}
	if len(args) > 0 {
		lines = append(lines, "SENSOR_ARGS="+strings.Join(args, " "))
	}
	for _, kv := range env {
		if !strings.Contains(kv, "=") || strings.ContainsAny(kv, "\r\n") {
			return nil, fmt.Errorf("a variavel de ambiente %q do sensor nao e CHAVE=valor numa linha so; migre a mao", kv)
		}
		lines = append(lines, kv)
	}
	return lines, nil
}
