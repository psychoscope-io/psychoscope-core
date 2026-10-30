package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateSensorToExternal(t *testing.T) {
	in := `{
	  "socket_mode": "0660",
	  "allowed_uids": [1000],
	  "modules": [
	    {"id": "mod-net-sensor", "path": "/usr/local/bin/mod-net-sensor", "args": ["-i", "wlp2s0", "--snaplen", "512"], "env": ["RUST_LOG=info"], "stop_grace": "20s"},
	    {"id": "outro", "path": "/opt/outro", "args": ["-x"]}
	  ],
	  "storage": {"retention_days": 7}
	}`
	r, err := MigrateSensorToExternal([]byte(in), "psychoscope-sensor")
	if err != nil || !r.Changed {
		t.Fatalf("err=%v changed=%v", err, r.Changed)
	}
	if got := strings.Join(r.SensorEnv, "|"); got != "SENSOR_ARGS=-i wlp2s0 --snaplen 512|RUST_LOG=info" {
		t.Errorf("sensor.env: %q", got)
	}
	// a configuracao nova tem de carregar pelo mesmo caminho estrito do Core
	var out struct {
		SocketMode string            `json:"socket_mode"`
		Allowed    []uint32          `json:"allowed_uids"`
		Modules    []json.RawMessage `json:"modules"`
		Storage    struct {
			Retention int `json:"retention_days"`
		} `json:"storage"`
	}
	if err := json.Unmarshal(r.Config, &out); err != nil || out.SocketMode != "0660" || len(out.Allowed) != 1 || out.Storage.Retention != 7 || len(out.Modules) != 2 {
		t.Fatalf("o resto da configuracao deve ficar igual: %v %+v", err, out)
	}
	cfg := loadFromBytes(t, r.Config)
	sensor, outro := cfg.Modules[0], cfg.Modules[1]
	if !sensor.External || sensor.User != "psychoscope-sensor" || sensor.Path != "" || len(sensor.Args) != 0 || sensor.StopGrace.String() != "20s" {
		t.Errorf("sensor migrado: %+v", sensor)
	}
	if outro.External || outro.Path != "/opt/outro" || len(outro.Args) != 1 {
		t.Errorf("outro modulo nao pode mudar: %+v", outro)
	}
}

func TestMigrateSensorNothingToDo(t *testing.T) {
	for name, in := range map[string]string{
		"ja externo":    `{"modules":[{"id":"mod-net-sensor","external":true,"user":"psychoscope-sensor"}]}`,
		"sem modulos":   `{}`,
		"outro binario": `{"modules":[{"id":"x","path":"/opt/outro"}]}`,
	} {
		r, err := MigrateSensorToExternal([]byte(in), "psychoscope-sensor")
		if err != nil || r.Changed {
			t.Errorf("%s: err=%v changed=%v", name, err, r.Changed)
		}
	}
}

func TestMigrateSensorRefusesWhenNotFaithful(t *testing.T) {
	for name, in := range map[string]string{
		"json invalido":      `{"modules":`,
		"modules invalido":   `{"modules":"x"}`,
		"dois sensores":      `{"modules":[{"id":"a","path":"/x/mod-net-sensor"},{"id":"b","path":"/y/mod-net-sensor"}]}`,
		"arg com espaco":     `{"modules":[{"id":"a","path":"/x/mod-net-sensor","args":["--bpf","tcp port 80"]}]}`,
		"arg com aspas":      `{"modules":[{"id":"a","path":"/x/mod-net-sensor","args":["--bpf","\"x\""]}]}`,
		"env sem igual":      `{"modules":[{"id":"a","path":"/x/mod-net-sensor","env":["SEMIGUAL"]}]}`,
		"env com quebra":     `{"modules":[{"id":"a","path":"/x/mod-net-sensor","env":["A=1\nB=2"]}]}`,
		"args nao e lista":   `{"modules":[{"id":"a","path":"/x/mod-net-sensor","args":"-i eth0"}]}`,
		"argumento em vazio": `{"modules":[{"id":"a","path":"/x/mod-net-sensor","args":[""]}]}`,
	} {
		if r, err := MigrateSensorToExternal([]byte(in), "psychoscope-sensor"); err == nil || r.Changed {
			t.Errorf("%s: deveria recusar (err=%v changed=%v)", name, err, r.Changed)
		}
	}
}

func loadFromBytes(t *testing.T, raw []byte) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load([]string{"-config", p}, env(0, nil))
	if err != nil {
		t.Fatalf("a configuracao migrada deve carregar: %v", err)
	}
	return c
}
