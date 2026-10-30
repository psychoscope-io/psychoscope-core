package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const oldConfig = `{"socket_mode":"0660","modules":[{"id":"mod-net-sensor","path":"/usr/local/bin/mod-net-sensor","args":["-i","eth0"]}]}`

func migrateDir(t *testing.T, cfg string) (conf, env string) {
	t.Helper()
	dir := t.TempDir()
	conf, env = filepath.Join(dir, "psychoscope.json"), filepath.Join(dir, "sensor.env")
	if err := os.WriteFile(conf, []byte(cfg), 0o640); err != nil {
		t.Fatal(err)
	}
	return conf, env
}

func TestMigrateConfigWritesBackupEnvAndConfig(t *testing.T) {
	conf, env := migrateDir(t, oldConfig)
	var out bytes.Buffer
	if err := migrateConfig(conf, env, "psychoscope-sensor", &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(conf + migrationBackupExt); string(b) != oldConfig {
		t.Errorf("o backup deve ser a configuracao original: %q", b)
	}
	if b, _ := os.ReadFile(env); !strings.Contains(string(b), "SENSOR_ARGS=-i eth0\n") {
		t.Errorf("sensor.env: %q", b)
	}
	if b, _ := os.ReadFile(conf); !strings.Contains(string(b), `"external": true`) || strings.Contains(string(b), `"path"`) {
		t.Errorf("configuracao migrada: %s", b)
	}
	if st, _ := os.Stat(conf); st.Mode().Perm() != 0o640 {
		t.Errorf("o modo da configuracao deve ser mantido: %v", st.Mode())
	}
	out.Reset()
	if err := migrateConfig(conf, env, "psychoscope-sensor", &out); err != nil || !strings.Contains(out.String(), "nada a migrar") {
		t.Errorf("migrar de novo deve ser inofensivo: %v %q", err, out.String())
	}
}

func TestMigrateConfigKeepsOperatorSensorEnv(t *testing.T) {
	conf, env := migrateDir(t, oldConfig)
	if err := os.WriteFile(env, []byte("SENSOR_ARGS=-i enp3s0\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := migrateConfig(conf, env, "psychoscope-sensor", &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(env); string(b) != "SENSOR_ARGS=-i enp3s0\n" {
		t.Errorf("o sensor.env do operador nao pode ser sobrescrito: %q", b)
	}
	if !strings.Contains(out.String(), "SENSOR_ARGS=-i eth0") {
		t.Errorf("deve mostrar o que o operador precisa conferir: %q", out.String())
	}
}

func TestMigrateConfigWritesNothingWhenNotFaithfulOrBackupExists(t *testing.T) {
	bad := `{"modules":[{"id":"a","path":"/x/mod-net-sensor","args":["--bpf","tcp port 80"]}]}`
	conf, env := migrateDir(t, bad)
	if err := migrateConfig(conf, env, "psychoscope-sensor", &bytes.Buffer{}); err == nil {
		t.Fatal("deveria recusar")
	}
	for _, p := range []string{conf + migrationBackupExt, env} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s nao deveria existir", p)
		}
	}
	if b, _ := os.ReadFile(conf); string(b) != bad {
		t.Error("a configuracao nao pode ser alterada")
	}

	conf, env = migrateDir(t, oldConfig)
	if err := os.WriteFile(conf+migrationBackupExt, []byte("antigo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateConfig(conf, env, "psychoscope-sensor", &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "ja existe") {
		t.Errorf("backup existente deve impedir: %v", err)
	}
	if b, _ := os.ReadFile(conf); string(b) != oldConfig {
		t.Error("a configuracao nao pode ser alterada")
	}
}

func TestMigrateConfigFailedEnvWriteLeavesNoBackupAndAllowsRetry(t *testing.T) {
	conf, env := migrateDir(t, oldConfig)
	missing := filepath.Join(filepath.Dir(env), "ausente", "sensor.env") // o diretorio nao existe: a gravacao falha
	if err := migrateConfig(conf, missing, "psychoscope-sensor", &bytes.Buffer{}); err == nil {
		t.Fatal("deveria falhar ao gravar o sensor.env")
	}
	if _, err := os.Stat(conf + migrationBackupExt); err == nil {
		t.Error("o backup nao pode ficar para tras: ele impediria repetir o comando")
	}
	if b, _ := os.ReadFile(conf); string(b) != oldConfig {
		t.Error("a configuracao nao pode ser alterada")
	}
	if err := migrateConfig(conf, env, "psychoscope-sensor", &bytes.Buffer{}); err != nil {
		t.Fatalf("repetir depois de corrigir o caminho deve funcionar: %v", err)
	}
}
