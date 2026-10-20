package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(euid int, vars map[string]string, usable ...string) Env {
	return Env{
		Getenv: func(k string) string { return vars[k] },
		Euid:   euid,
		DirUsable: func(d string) bool {
			for _, u := range usable {
				if u == d {
					return true
				}
			}
			return false
		},
	}
}

func TestDefaultSocketDir(t *testing.T) {
	cases := []struct {
		name string
		e    Env
		want string
	}{
		{"root", env(0, nil), "/var/run/psychoscope"},
		{"dir existente e gravavel (systemd RuntimeDirectory)", env(1000, map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}, "/var/run/psychoscope"), "/var/run/psychoscope"},
		{"dev: XDG", env(1000, map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}), "/run/user/1000/psychoscope"},
		{"sem XDG", env(1000, nil), "/var/run/psychoscope"},
	}
	for _, c := range cases {
		if got := DefaultSocketDir(c.e); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestLoadPrecedence(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "c.json")
	os.WriteFile(file, []byte(`{"socket":"/file/core.sock","ctl_socket":"/file/ctl.sock","log_level":"warn"}`), 0o600)
	e := env(1000, map[string]string{EnvSocket: "/env/core.sock"})

	c, err := Load([]string{"-config", file, "-socket", "/flag/core.sock"}, e)
	if err != nil {
		t.Fatal(err)
	}
	if c.SocketPath != "/flag/core.sock" {
		t.Errorf("flag deve vencer: %s", c.SocketPath)
	}
	if c.CtlSocketPath != "/file/ctl.sock" || c.LogLevel != "warn" {
		t.Errorf("arquivo deve preencher o resto: %+v", c)
	}

	c, err = Load([]string{"-config", file}, e)
	if err != nil || c.SocketPath != "/env/core.sock" {
		t.Errorf("env deve vencer arquivo: %v %v", c, err)
	}
}

func TestLoadModulesAndDefaults(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "c.json")
	os.WriteFile(file, []byte(`{"modules":[{"id":"mod-net-sensor","path":"/bin/true","args":["-x"],"stop_grace":"2s"}]}`), 0o600)
	c, err := Load([]string{"-config", file}, env(0, nil))
	if err != nil {
		t.Fatal(err)
	}
	m := c.Modules[0]
	if m.StopGrace != 2*time.Second || m.MinBackoff != time.Second || m.MaxBackoff != 30*time.Second || m.ConnectTimeout != 15*time.Second {
		t.Errorf("defaults/overrides errados: %+v", m)
	}
	if c.SocketMode != 0o660 || c.StatusInterval != 5*time.Second {
		t.Errorf("defaults globais: %+v", c)
	}
}

func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "x.json")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	cases := map[string]string{
		"campo desconhecido":      `{"bogus":1}`,
		"modo com bits de outros": `{"socket_mode":"0666"}`,
		"modo nao octal":          `{"socket_mode":"abc"}`,
		"id invalido":             `{"modules":[{"id":"../x","path":"/bin/true"}]}`,
		"id duplicado":            `{"modules":[{"id":"a","path":"/x"},{"id":"a","path":"/y"}]}`,
		"sem path":                `{"modules":[{"id":"a"}]}`,
		"backoff invertido":       `{"modules":[{"id":"a","path":"/x","restart_min_backoff":"10s","restart_max_backoff":"1s"}]}`,
		"duracao invalida":        `{"status_interval":"5 segundos"}`,
		"log invalido":            `{"log_level":"trace"}`,
		"sockets iguais":          `{"socket":"/a","ctl_socket":"/a"}`,
	}
	for name, body := range cases {
		if _, err := Load([]string{"-config", write(body)}, env(0, nil)); err == nil {
			t.Errorf("%s: esperado erro", name)
		}
	}
	if _, err := Load([]string{"extra"}, env(0, nil)); err == nil || !strings.Contains(err.Error(), "inesperados") {
		t.Errorf("argumento posicional deve falhar: %v", err)
	}
}

func TestDetectionDefaultsOverlayAndValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "d.json")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	c, err := Load([]string{"-config", write(`{}`)}, env(0, nil))
	if err != nil {
		t.Fatal(err)
	}
	d := c.Detection
	if d.Window != time.Minute || d.Rules.Scan.VerticalPorts != 15 || d.Rules.Tunnel.MinEntropy != 3.2 || d.QueueSize != 4096 {
		t.Fatalf("defaults: %+v", d)
	}

	c, err = Load([]string{"-config", write(`{"detection":{"window":"2m","disabled":["net.dns.tunnel"],
		"scan":{"vertical_ports":30,"window":"20s"},"nxdomain":{"min_responses":50},
		"tunnel":{"min_entropy":4.0,"allowed_bases":["cdn.example"]}}}`)}, env(0, nil))
	if err != nil {
		t.Fatal(err)
	}
	d = c.Detection
	if d.Window != 2*time.Minute || d.Rules.Scan.VerticalPorts != 30 || d.Rules.Scan.Window != 20*time.Second ||
		d.Rules.Scan.HorizontalHosts != 20 || d.Rules.NXDomain.MinResponses != 50 || d.Rules.NXDomain.MinDistinct != 8 ||
		d.Rules.Tunnel.MinEntropy != 4.0 || len(d.Rules.Disabled) != 1 || d.Rules.Tunnel.AllowedBases[0] != "cdn.example" {
		t.Fatalf("overlay: %+v", d)
	}

	for name, body := range map[string]string{
		"janela menor que a regra": `{"detection":{"window":"5s"}}`,
		"regra inexistente":        `{"detection":{"disabled":["net.x"]}}`,
		"duracao invalida":         `{"detection":{"scan":{"window":"dez"}}}`,
		"campo desconhecido":       `{"detection":{"bogus":1}}`,
		"limiar negativo":          `{"detection":{"scan":{"vertical_ports":-1}}}`,
	} {
		if _, err := Load([]string{"-config", write(body)}, env(0, nil)); err == nil {
			t.Errorf("%s: esperado erro", name)
		}
	}
}
