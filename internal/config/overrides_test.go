package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
)

type rulesConfig = rules.Config

// baseConfig carrega uma configuracao base com listas preenchidas, para provar que Layer
// nao as altera.
func baseConfig(t *testing.T) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "base.json")
	body := `{"detection":{"disabled":["net.icmp.sweep"],"beacon":{"ignore_ports":[123,443],"ignore_destinations":["10.0.0.0/8"]},
		"tunnel":{"allowed_bases":["cdn.example"]}},"storage":{"retention_days":10}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load([]string{"-config", p}, env(0, nil))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ov(t *testing.T, kv ...string) Overrides {
	t.Helper()
	o := Overrides{}
	for i := 0; i < len(kv); i += 2 {
		o[kv[i]] = json.RawMessage(kv[i+1])
	}
	return o
}

func TestLayerAppliesOverridesAndLeavesTheBaseUntouched(t *testing.T) {
	base := baseConfig(t)
	snapshot := *base
	snapshot.Detection.Rules = cloneRules(t, base.Detection.Rules)

	c, err := Layer(base, ov(t,
		"detection.scan.vertical_ports", "30",
		"detection.window", `"2m"`,
		"detection.scan.window", `"90s"`,
		"detection.disabled", `[]`,
		"detection.beacon.ignore_ports", `[9999]`,
		"detection.tunnel.allowed_bases", `["a.example","b.example"]`,
		"storage.max_alerts", "500",
	))
	if err != nil {
		t.Fatal(err)
	}
	d := c.Detection
	if d.Rules.Scan.VerticalPorts != 30 || d.Window != 2*time.Minute || d.Rules.Scan.Window != 90*time.Second ||
		len(d.Rules.Disabled) != 0 || !reflect.DeepEqual(d.Rules.Beacon.IgnorePorts, []int{9999}) ||
		len(d.Rules.Tunnel.AllowedBases) != 2 || c.Storage.MaxAlerts != 500 {
		t.Fatalf("ajustes nao aplicados: %+v / %+v", d, c.Storage)
	}
	// o que nao foi ajustado vem da base (arquivo): retention_days=10 e a lista de destinos
	if c.Storage.RetentionDays != 10 || !reflect.DeepEqual(d.Rules.Beacon.IgnoreDestinations, []string{"10.0.0.0/8"}) {
		t.Fatalf("a base deve valer onde nao ha ajuste: %+v", c)
	}
	// a base nao pode ter sido tocada, nem nas listas (o vetor da fatia nao pode ser reaproveitado)
	if !reflect.DeepEqual(base.Detection.Rules, snapshot.Detection.Rules) || base.Storage != snapshot.Storage || base.Detection.Window != snapshot.Detection.Window {
		t.Fatalf("Layer alterou a base:\n antes %+v\n depois %+v", snapshot.Detection.Rules, base.Detection.Rules)
	}
}

// cloneRules copia as listas de rules.Config por JSON (so para o teste comparar antes/depois).
func cloneRules(t *testing.T, r any) (out rulesConfig) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLayerRejectsWhatIsNotEditable(t *testing.T) {
	base := baseConfig(t)
	for path, val := range map[string]string{
		"detection.queue_size":     "1",
		"detection.max_events":     "1",
		"storage.path":             `"/etc/passwd"`,
		"storage.enabled":          "false",
		"modules":                  `[]`,
		"modules.0.path":           `"/bin/sh"`,
		"socket_mode":              `"0666"`,
		"detection.bogus.x":        "1",
		"detection.scan.bogus":     "1",
		"detection.window.extra":   "1",
		"detection.scan":           `{}`, // secao inteira: o caminho tem de chegar ao campo
		"detection":                `{}`,
		"storage.retention_days.x": "1",
	} {
		_, err := Layer(base, ov(t, path, val))
		if err == nil {
			t.Errorf("%s deveria ser recusado", path)
			continue
		}
		if !strings.Contains(err.Error(), "nao editavel") && !strings.Contains(err.Error(), "desconhecido") {
			t.Errorf("%s: mensagem pouco acionavel: %v", path, err)
		}
	}
}

func TestLayerValidatesTheWholeConfigAndNamesTheField(t *testing.T) {
	base := baseConfig(t)
	// janela de regra maior que detection.window (60s): valida em conjunto
	if _, err := Layer(base, ov(t, "detection.scan.window", `"5m"`)); err == nil || !strings.Contains(err.Error(), "detection.window") {
		t.Fatalf("janela da regra maior que a detection.window: %v", err)
	}
	// as duas juntas passam
	if _, err := Layer(base, ov(t, "detection.scan.window", `"5m"`, "detection.window", `"5m"`)); err != nil {
		t.Fatalf("janelas coerentes: %v", err)
	}
	for path, val := range map[string]string{
		"detection.scan.vertical_ports":        "-1",
		"detection.scan.vertical_ports ":       "1",
		"detection.beacon.ignore_destinations": `["nao-e-ip"]`,
		"detection.nxdomain.ignore_suffixes":   `[".arpa"]`,
		"detection.scan.window":                `"dez"`,
		"storage.max_alerts":                   `"muitos"`,
		"storage.retention_days":               "-5",
		"detection.disabled":                   `["net.inexistente"]`,
	} {
		_, err := Layer(base, ov(t, path, val))
		if err == nil {
			t.Errorf("%s=%s deveria falhar", path, val)
		}
	}
}

func TestOverridesParseAndSerializeRoundTrip(t *testing.T) {
	in := `{"detection":{"window":"2m","scan":{"vertical_ports":30},"beacon":{"ignore_ports":[1,2]}},"storage":{"max_alerts":7}}`
	o, err := ParseOverrides([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"detection.window", "detection.scan.vertical_ports", "detection.beacon.ignore_ports", "storage.max_alerts"} {
		if _, ok := o[path]; !ok {
			t.Errorf("caminho %s ausente apos achatar: %v", path, o.paths())
		}
	}
	out, err := o.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	_ = json.Unmarshal([]byte(in), &a)
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("ida e volta mudou o conteudo:\n%s", out)
	}
	out2, _ := o.JSON()
	if string(out) != string(out2) {
		t.Fatal("serializacao deve ser deterministica")
	}
	if empty, _ := (Overrides{}).JSON(); strings.TrimSpace(string(empty)) != "{}" {
		t.Fatalf("sem ajustes: %s", empty)
	}
	if _, err := (Overrides{"modules": json.RawMessage(`[]`)}).JSON(); err == nil {
		t.Fatal("caminho fora do formato nao pode ser serializado")
	}
}

func TestReadOverrides(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "overrides.json")

	if o, err := ReadOverrides(p); err != nil || len(o) != 0 {
		t.Fatalf("arquivo ausente = sem ajustes: %v %v", o, err)
	}
	for name, body := range map[string]string{
		"chave desconhecida no topo": `{"modules":[{"id":"x","path":"/bin/sh"}]}`,
		"json quebrado":              `{"detection":`,
		"secao nao objeto":           `{"detection":{"scan":{"window":}}}`,
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadOverrides(p)
		if err == nil || !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "remova") {
			t.Errorf("%s: erro deve citar o arquivo e dizer como sair do problema: %v", name, err)
		}
	}
	// grande demais
	if err := os.WriteFile(p, append([]byte(`{"storage":{"max_alerts":1},"x":"`), make([]byte, maxOverridesSize)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOverrides(p); err == nil || !strings.Contains(err.Error(), "grande demais") {
		t.Fatalf("limite de tamanho: %v", err)
	}
	// valido
	if err := os.WriteFile(p, []byte(`{"storage":{"max_alerts":3}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if o, err := ReadOverrides(p); err != nil || string(o["storage.max_alerts"]) != "3" {
		t.Fatalf("valido: %v %v", o, err)
	}
}
