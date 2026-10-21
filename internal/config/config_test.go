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

func TestStorageAndMetricsConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "s.json")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	e := env(1000, map[string]string{"XDG_STATE_HOME": "/home/u/.state"})
	c, err := Load([]string{"-config", write(`{}`)}, e)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Storage.Enabled || c.Storage.Path != "/home/u/.state/psychoscope/alerts.db" || c.Storage.RetentionDays != 30 ||
		c.Storage.MaxAlerts != 100_000 || c.Metrics.Listen != "" {
		t.Fatalf("defaults: %+v %+v", c.Storage, c.Metrics)
	}
	if c.Storage.Retention() != 30*24*time.Hour {
		t.Fatal("Retention")
	}

	c, err = Load([]string{"-config", write(`{"storage":{"enabled":false,"path":"/x/a.db","retention_days":0,"max_alerts":5},
		"metrics":{"listen":"127.0.0.1:9464"}}`)}, e)
	if err != nil || c.Storage.Enabled || c.Storage.Path != "/x/a.db" || c.Storage.RetentionDays != 0 || c.Storage.MaxAlerts != 5 ||
		c.Metrics.Listen != "127.0.0.1:9464" {
		t.Fatalf("overlay: %+v %+v %v", c.Storage, c.Metrics, err)
	}
	for _, l := range []string{"localhost:9464", "[::1]:9464"} {
		if _, err := Load([]string{"-config", write(`{"metrics":{"listen":"` + l + `"}}`)}, e); err != nil {
			t.Errorf("%s deveria ser aceito: %v", l, err)
		}
	}
	for name, body := range map[string]string{
		"exposto sem autenticacao": `{"metrics":{"listen":"0.0.0.0:9464"}}`,
		"sem host":                 `{"metrics":{"listen":":9464"}}`,
		"hostname externo":         `{"metrics":{"listen":"example.com:9464"}}`,
		"sem porta":                `{"metrics":{"listen":"127.0.0.1"}}`,
		"retencao negativa":        `{"storage":{"retention_days":-1}}`,
		"campo desconhecido":       `{"storage":{"bogus":1}}`,
	} {
		if _, err := Load([]string{"-config", write(body)}, e); err == nil {
			t.Errorf("%s: esperado erro", name)
		}
	}
	if _, err := Load([]string{"-config", write(`{"metrics":{"listen":"0.0.0.0:9464","allow_non_loopback":true}}`)}, e); err != nil {
		t.Errorf("allow_non_loopback deveria liberar: %v", err)
	}
}

func TestDefaultStateDir(t *testing.T) {
	cases := []struct {
		name string
		e    Env
		want string
	}{
		{"root", env(0, nil), "/var/lib/psychoscope"},
		{"StateDirectory do systemd", env(1000, map[string]string{"HOME": "/home/u"}, "/var/lib/psychoscope"), "/var/lib/psychoscope"},
		{"XDG_STATE_HOME", env(1000, map[string]string{"XDG_STATE_HOME": "/s", "HOME": "/home/u"}), "/s/psychoscope"},
		{"HOME", env(1000, map[string]string{"HOME": "/home/u"}), "/home/u/.local/state/psychoscope"},
		{"nada", env(1000, nil), "/var/lib/psychoscope"},
	}
	for _, c := range cases {
		if got := DefaultStateDir(c.e); got != c.want {
			t.Errorf("%s: %q != %q", c.name, got, c.want)
		}
	}
}

func TestDetectionNewRuleSections(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "d.json")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	c, err := Load([]string{"-config", write(`{"detection":{
		"tls":{"cooldown":"20m","allowed_bases":["cdn.example"],"min_entropy":3.9},
		"beacon":{"min_samples":12,"max_cv":0.1,"ignore_domains":["windowsupdate.com"],"ignore_ports":[123,5353]},
		"bruteforce":{"ports":[22,2222],"ignore_sources":["10.9.0.0/16"],"min_attempts":20},
		"icmp_sweep":{"min_hosts":50,"window":"30s"},
		"dns_rate":{"min_queries":500},
		"disabled":["net.beacon"]}}`)}, env(0, nil))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Detection.Rules
	if r.TLS.Cooldown != 20*time.Minute || r.TLS.AllowedBases[0] != "cdn.example" || r.TLS.MinEntropy != 3.9 || r.TLS.MissingSNIMin != 3 ||
		r.Beacon.MinSamples != 12 || r.Beacon.MaxCV != 0.1 || r.Beacon.IgnorePorts[1] != 5353 || r.Beacon.MaxInterval != time.Hour ||
		len(r.BruteForce.Ports) != 2 || r.BruteForce.MinAttempts != 20 || r.BruteForce.IgnoreSources[0] != "10.9.0.0/16" ||
		r.ICMPSweep.MinHosts != 50 || r.ICMPSweep.Window != 30*time.Second || r.DNSRate.MinQueries != 500 || r.DNSRate.Window != 10*time.Second ||
		r.Disabled[0] != "net.beacon" {
		t.Fatalf("overlay das novas secoes: %+v", r)
	}
	for name, body := range map[string]string{
		"campo desconhecido na secao":          `{"detection":{"beacon":{"max_cvv":0.1}}}`,
		"secao desconhecida":                   `{"detection":{"beaconing":{}}}`,
		"tipo errado":                          `{"detection":{"bruteforce":{"ports":"22"}}}`,
		"fonte invalida":                       `{"detection":{"bruteforce":{"ignore_sources":["xyz"]}}}`,
		"janela de regra maior que a do motor": `{"detection":{"window":"30s","icmp_sweep":{"window":"45s"}}}`,
		"min_samples invalido":                 `{"detection":{"beacon":{"min_samples":2}}}`,
	} {
		if _, err := Load([]string{"-config", write(body)}, env(0, nil)); err == nil {
			t.Errorf("%s: esperado erro", name)
		}
	}
	_, err = Load([]string{"-config", write(`{"detection":{"beacon":{"max_cvv":0.1}}}`)}, env(0, nil))
	if err == nil || !strings.Contains(err.Error(), "detection.beacon") || !strings.Contains(err.Error(), "max_cv") {
		t.Errorf("a mensagem deve apontar a secao e listar os campos validos: %v", err)
	}
}

func TestNXDomainIgnoreSuffixesFromFile(t *testing.T) {
	dir := t.TempDir()
	load := func(body string) (*Config, error) {
		p := filepath.Join(dir, "n.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load([]string{"-config", p}, env(0, nil))
	}
	c, err := load(`{}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Detection.Rules.NXDomain.IgnoreSuffixes; len(got) != 2 || got[0] != "in-addr.arpa" || got[1] != "ip6.arpa" {
		t.Fatalf("padrao: %v", got)
	}
	// a lista do arquivo substitui o padrao; lista vazia conta todos os nomes
	for body, want := range map[string]int{
		`{"detection":{"nxdomain":{"ignore_suffixes":["corp.example"]}}}`: 1,
		`{"detection":{"nxdomain":{"ignore_suffixes":[]}}}`:               0,
	} {
		c, err := load(body)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if got := c.Detection.Rules.NXDomain.IgnoreSuffixes; len(got) != want {
			t.Errorf("%s: %v", body, got)
		}
	}
	if _, err := load(`{"detection":{"nxdomain":{"ignore_suffixes":[".arpa"]}}}`); err == nil || !strings.Contains(err.Error(), "ignore_suffixes") {
		t.Fatalf("sufixo com ponto inicial deve ser recusado com mensagem acionavel: %v", err)
	}
}

func TestBeaconIgnoreDestinationsFromFile(t *testing.T) {
	dir := t.TempDir()
	load := func(body string) (*Config, error) {
		p := filepath.Join(dir, "b.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load([]string{"-config", p}, env(0, nil))
	}
	c, err := load(`{"detection":{"beacon":{"ignore_destinations":["149.154.160.0/20","2001:67c:4e8::/48"]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Detection.Rules.Beacon.IgnoreDestinations; len(got) != 2 || got[0] != "149.154.160.0/20" {
		t.Fatalf("ignore_destinations: %v", got)
	}
	if _, err := load(`{"detection":{"beacon":{"ignore_destinations":["telegram"]}}}`); err == nil ||
		!strings.Contains(err.Error(), "ignore_destinations") || !strings.Contains(err.Error(), "telegram") {
		t.Fatalf("valor invalido deve ser recusado citando o campo e o valor: %v", err)
	}
}
