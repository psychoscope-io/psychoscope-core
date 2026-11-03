package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	"github.com/psychoscope-io/psychoscope-core/internal/detection/ruletest"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func burstRules(mutate func(*Config)) func(*testing.T) []detection.Rule {
	return func(t *testing.T) []detection.Rule {
		t.Helper()
		c := Default()
		mutate(&c)
		rs, err := Build(c)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}
}

func failures(n int, user string, step float64) []ruletest.Input {
	var in []ruletest.Input
	for i := 0; i < n; i++ {
		in = append(in, ruletest.Gen(float64(i)*step, "login.falha", map[string]string{"usuario": user}))
	}
	return in
}

func TestGenericBurstIsInactiveByDefault(t *testing.T) {
	ruletest.Table(t, burstRules(func(*Config) {}), []ruletest.Case{
		{Name: "sem types a regra nao faz nada", Inputs: failures(200, "ana", 0.1)},
	})
}

func TestGenericBurstTable(t *testing.T) {
	watch := func(c *Config) { c.GenericBurst.Types = []string{"login.falha"} }
	byUser := func(c *Config) { watch(c); c.GenericBurst.GroupBy = []string{"usuario"} }
	other := func(sec float64) ruletest.Input {
		return ruletest.Gen(sec, "login.ok", map[string]string{"usuario": "ana"})
	}
	ctx := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	t.Run("sem agrupamento", func(t *testing.T) {
		ruletest.Table(t, burstRules(watch), []ruletest.Case{
			{Name: "abaixo do limiar", Inputs: failures(9, "ana", 1)},
			{Name: "no limiar dispara uma vez", Inputs: failures(10, "ana", 1),
				Want: []ruletest.Want{{Rule: NameGenericBurst, Severity: psychoscopev1.Severidade_SEVERIDADE_MEDIA,
					Context: ctx("modulo", "mod-test", "evento_tipo", "login.falha", "ocorrencias", "10", "janela", "1m0s")}}},
			{Name: "cooldown evita repetir", Inputs: failures(30, "ana", 1),
				Want: []ruletest.Want{{Rule: NameGenericBurst}}},
			{Name: "usuarios diferentes somam sem group_by", Inputs: append(failures(5, "ana", 1), failures(5, "bia", 1)...),
				Want: []ruletest.Want{{Rule: NameGenericBurst}}},
			{Name: "tipo nao vigiado", Inputs: func() []ruletest.Input {
				var in []ruletest.Input
				for i := 0; i < 50; i++ {
					in = append(in, other(float64(i)))
				}
				return in
			}()},
			{Name: "fora da janela", Inputs: failures(10, "ana", 7)}, // 10 eventos em 63 s: nunca 10 em 60 s
		})
	})
	t.Run("agrupado por usuario", func(t *testing.T) {
		mixed := ruletest.Gen(2.5, "login.falha", map[string]string{"usuario": "bia"})
		ruletest.Table(t, burstRules(byUser), []ruletest.Case{
			{Name: "usuarios diferentes nao se somam", Inputs: append(failures(9, "ana", 1), failures(9, "bia", 1)...)},
			{Name: "um usuario na rajada", Inputs: append([]ruletest.Input{mixed}, failures(10, "ana", 1)...),
				Want: []ruletest.Want{{Rule: NameGenericBurst, Context: ctx("grupo", "usuario=ana", "grupo_valor", "ana", "ocorrencias", "10")}}},
			{Name: "dois usuarios, dois alertas", Inputs: append(failures(10, "ana", 1), failures(10, "bia", 1)...),
				Want: []ruletest.Want{{Rule: NameGenericBurst, Context: ctx("grupo_valor", "ana")}, {Rule: NameGenericBurst, Context: ctx("grupo_valor", "bia")}}},
		})
	})
	t.Run("grupos ignorados", func(t *testing.T) {
		ignore := func(c *Config) { byUser(c); c.GenericBurst.IgnoreGroups = []string{"svc-backup"} }
		ruletest.Table(t, burstRules(ignore), []ruletest.Case{
			{Name: "conta ignorada", Inputs: failures(40, "svc-backup", 1)},
			{Name: "outra conta continua alertando", Inputs: failures(10, "ana", 1), Want: []ruletest.Want{{Rule: NameGenericBurst}}},
		})
	})
	t.Run("modulos diferentes nao se somam", func(t *testing.T) {
		var in []ruletest.Input
		for i := 0; i < 20; i++ {
			e := ruletest.Gen(float64(i), "login.falha", nil)
			e.Module = []string{"mod-a", "mod-b"}[i%2]
			in = append(in, e)
		}
		ruletest.Table(t, burstRules(watch), []ruletest.Case{{Name: "10 em cada um dos dois", Inputs: in,
			Want: []ruletest.Want{{Rule: NameGenericBurst, Context: ctx("modulo", "mod-a")}, {Rule: NameGenericBurst, Context: ctx("modulo", "mod-b")}}}})
	})
}

func TestGenericBurstConfigValidation(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"tipo com maiuscula": func(c *Config) { c.GenericBurst.Types = []string{"Login"} },
		"tipo vazio":         func(c *Config) { c.GenericBurst.Types = []string{""} },
		"group_by invalido":  func(c *Config) { c.GenericBurst.GroupBy = []string{"com espaco"} },
		"min_events zero":    func(c *Config) { c.GenericBurst.MinEvents = 0 },
		"janela zero":        func(c *Config) { c.GenericBurst.Window = 0 },
		"cooldown zero":      func(c *Config) { c.GenericBurst.Cooldown = 0 },
	} {
		c := Default()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: deveria ser recusado", name)
		} else if !strings.Contains(err.Error(), "generic_burst") {
			t.Errorf("%s: o erro deveria citar a secao: %v", name, err)
		}
	}
	c := Default()
	c.GenericBurst.Types = []string{"login.falha", "acesso.negado"}
	c.GenericBurst.GroupBy = []string{"usuario", "origem-ip"}
	if err := c.Validate(); err != nil {
		t.Errorf("configuracao valida recusada: %v", err)
	}
	if c.LongestWindow() < c.GenericBurst.Window {
		t.Error("detection.window precisa cobrir a janela da regra")
	}
}

func TestSuggestedExceptionForGenericBurst(t *testing.T) {
	cfg := Default()
	cfg.GenericBurst.Types = []string{"login.falha"}
	cfg.GenericBurst.GroupBy = []string{"usuario"}
	rs, _ := Build(cfg)
	as := ruletest.Run(t, rs, failures(10, "svc-backup", 1)...)
	if len(as) != 1 {
		t.Fatalf("esperava um alerta: %v", as)
	}
	field, value, ok := Exception(as[0])
	if !ok || field != FieldGenericBurstIgnoreGroups || value != "svc-backup" {
		t.Fatalf("excecao: (%q, %q, %v)", field, value, ok)
	}
	cfg.GenericBurst.IgnoreGroups = []string{value}
	rs, _ = Build(cfg)
	if got := ruletest.Run(t, rs, failures(10, "svc-backup", 1)...); len(got) != 0 {
		t.Errorf("aplicar a sugestao deveria silenciar o grupo: %v", got)
	}
	if got := ruletest.Run(t, rs, failures(10, "ana", 1)...); len(got) != 1 {
		t.Errorf("outro grupo deve continuar alertando: %v", got)
	}
	multi := Default()
	multi.GenericBurst.Types, multi.GenericBurst.GroupBy = []string{"login.falha"}, []string{"usuario", "origem-ip"}
	rs, _ = Build(multi)
	in := ruletest.Gen(0, "login.falha", map[string]string{"usuario": "ana", "origem-ip": "192.0.2.1"})
	var many []ruletest.Input
	for i := 0; i < 10; i++ {
		e := in
		e.Generic = &psychoscopev1.EventoGenerico{Tipo: "login.falha", Timestamp: ruletest.At(float64(i)), Atributos: in.Generic.Atributos}
		many = append(many, e)
	}
	as = ruletest.Run(t, rs, many...)
	if len(as) != 1 {
		t.Fatalf("esperava um alerta: %v", as)
	}
	if _, _, ok := Exception(as[0]); ok {
		t.Error("com mais de um atributo em group_by nao ha excecao inequivoca para sugerir")
	}
}

func TestGenericBurstKeysNeverCollideAcrossGroups(t *testing.T) {
	cfg := Default().GenericBurst
	cfg.Types, cfg.GroupBy = []string{"t"}, []string{"a", "b"}
	r := NewGenericBurst(cfg)
	ev := func(a, b string) *detection.Event {
		return &detection.Event{Module: "m", Generic: &psychoscopev1.EventoGenerico{Tipo: "t", Atributos: map[string]string{"a": a, "b": b}}}
	}
	k1, _ := r.Key(ev("x|y", "z"))
	k2, _ := r.Key(ev("x", "y|z"))
	k3, _ := r.Key(ev("x", "y"))
	if k1 == k2 || k1 == k3 || k2 == k3 {
		t.Fatalf("chaves de grupos diferentes colidiram: %q %q %q", k1, k2, k3)
	}
}

func TestGenericBurstStateIsBoundedByMaxKeys(t *testing.T) {
	cfg := Default().GenericBurst
	cfg.Types, cfg.GroupBy, cfg.MaxKeys = []string{"t"}, []string{"usuario"}, 100
	r := NewGenericBurst(cfg)
	for i := 0; i < 5000; i++ {
		ev := &detection.Event{Module: "m", At: ruletest.T0.Add(time.Duration(i) * time.Millisecond),
			Generic: &psychoscopev1.EventoGenerico{Tipo: "t", Atributos: map[string]string{"usuario": fmt.Sprint("u", i)}}}
		r.Eval(ev, nil)
		if len(r.series) > cfg.MaxKeys {
			t.Fatalf("o estado passou do teto: %d series", len(r.series))
		}
	}
	// um grupo novo e acompanhado normalmente depois do despejo
	var alerts int
	for i := 0; i < cfg.MinEvents; i++ {
		ev := &detection.Event{Module: "m", At: ruletest.T0.Add(10*time.Second + time.Duration(i)*time.Millisecond),
			Generic: &psychoscopev1.EventoGenerico{Tipo: "t", Atributos: map[string]string{"usuario": "alvo"}}}
		if r.Eval(ev, nil) != nil {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("a rajada de um grupo novo deveria alertar uma vez: %d", alerts)
	}
}

func TestGenericBurstMaxKeysValidation(t *testing.T) {
	c := Default()
	c.GenericBurst.MaxKeys = 99
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "max_keys") {
		t.Errorf("max_keys abaixo de 100 deveria ser recusado: %v", err)
	}
}
