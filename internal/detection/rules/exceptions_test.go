package rules

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func al(rule string, ctx map[string]string) *psychoscopev1.Alerta {
	return &psychoscopev1.Alerta{Regra: rule, Contexto: ctx}
}

func TestExceptionMapsEachRuleToItsList(t *testing.T) {
	for name, tc := range map[string]struct {
		a         *psychoscopev1.Alerta
		wantField string
		wantValue string
		ok        bool
	}{
		"beacon tcp IPv4":            {al(NameBeacon, map[string]string{"tipo": "tcp", "alvo": "149.154.166.110:443"}), FieldBeaconIgnoreDestinations, "149.154.166.110", true},
		"beacon tcp IPv6 (varios :)": {al(NameBeacon, map[string]string{"tipo": "tcp", "alvo": "2001:67c:4e8:f004::9:443"}), FieldBeaconIgnoreDestinations, "2001:67c:4e8:f004::9", true},
		"beacon dns":                 {al(NameBeacon, map[string]string{"tipo": "dns", "alvo": "c2.evil.example"}), FieldBeaconIgnoreDomains, "c2.evil.example", true},
		"bruteforce":                 {al(NameBruteForce, map[string]string{"origem": "10.0.0.66", "destino": "10.0.0.2"}), FieldBruteForceIgnoreSources, "10.0.0.66", true},
		"tunnel":                     {al(NameDNSTunnel, map[string]string{"dominio_base": "evil-tunnel.com"}), FieldTunnelAllowedBases, "evil-tunnel.com", true},
		"varredura nao tem lista":    {al(NameScanSYN, map[string]string{"origem": "10.0.0.66"}), "", "", false},
		"regra desconhecida":         {al("outra.regra", map[string]string{"alvo": "1.2.3.4:80"}), "", "", false},
		"beacon tcp sem porta":       {al(NameBeacon, map[string]string{"tipo": "tcp", "alvo": "149.154.166.110"}), "", "", false},
		"beacon tcp alvo vazio":      {al(NameBeacon, map[string]string{"tipo": "tcp", "alvo": ""}), "", "", false},
		"beacon tcp nao e IP":        {al(NameBeacon, map[string]string{"tipo": "tcp", "alvo": "host:443"}), "", "", false},
		"beacon sem tipo":            {al(NameBeacon, map[string]string{"alvo": "1.2.3.4:80"}), "", "", false},
		"beacon dns sem alvo":        {al(NameBeacon, map[string]string{"tipo": "dns"}), "", "", false},
		"bruteforce origem ruim":     {al(NameBruteForce, map[string]string{"origem": "nao-ip"}), "", "", false},
		"tunnel sem base":            {al(NameDNSTunnel, map[string]string{}), "", "", false},
		"alerta vazio":               {&psychoscopev1.Alerta{}, "", "", false},
	} {
		f, v, ok := Exception(tc.a)
		if f != tc.wantField || v != tc.wantValue || ok != tc.ok {
			t.Errorf("%s: (%q, %q, %v), esperado (%q, %q, %v)", name, f, v, ok, tc.wantField, tc.wantValue, tc.ok)
		}
	}
}

// listField resolve um caminho do catalogo (detection.<secao>.<chave>) para o campo []string.
func listField(t *testing.T, c *Config, path string) reflect.Value {
	t.Helper()
	parts := strings.Split(path, ".")
	if len(parts) != 3 || parts[0] != "detection" {
		t.Fatalf("caminho %q fora do formato detection.secao.chave", path)
	}
	sec, ok := c.Sections()[parts[1]]
	if !ok {
		t.Fatalf("secao %q inexistente", parts[1])
	}
	st := reflect.ValueOf(sec).Elem()
	for i := 0; i < st.NumField(); i++ {
		if strings.Split(st.Type().Field(i).Tag.Get("json"), ",")[0] == parts[2] {
			f := st.Field(i)
			if f.Kind() != reflect.Slice || f.Type().Elem().Kind() != reflect.String {
				t.Fatalf("%s nao e uma lista de texto", path)
			}
			return f
		}
	}
	t.Fatalf("campo %q inexistente na secao %q", parts[2], parts[1])
	return reflect.Value{}
}

// Prova de ponta a ponta: para cada regra, gera o alerta, aplica a excecao sugerida e confere
// que o mesmo trafego deixa de alertar, mas que outro destino igual continua alertando.
func TestSuggestedExceptionSilencesTheSameTrafficOnly(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for name, tc := range map[string]struct {
		traffic func(who string) []*psychoscopev1.EventoFluxoRede
		who     string // o que a excecao deve cobrir
		other   string // algo equivalente que NAO deve ser coberto
		rule    string
	}{
		"beacon tcp IPv4": {func(w string) []*psychoscopev1.EventoFluxoRede {
			return beatsTCP("192.168.0.8", w, 443, 0, 91, 0, 12, nil)
		}, "149.154.166.110", "149.154.166.111", NameBeacon},
		"beacon tcp IPv6": {func(w string) []*psychoscopev1.EventoFluxoRede {
			return beatsTCP("2804:29b8::1", w, 443, 0, 91, 0, 12, nil)
		}, "2001:67c:4e8:f004::9", "2001:67c:4e9::9", NameBeacon},
		"beacon dns": {func(w string) []*psychoscopev1.EventoFluxoRede {
			var evs []*psychoscopev1.EventoFluxoRede
			for i := 0; i < 10; i++ {
				evs = append(evs, dnsQuery(float64(i)*60, "10.0.0.5", w))
			}
			return evs
		}, "c2.evil.example", "c2.other.example", NameBeacon},
		"bruteforce": {func(w string) []*psychoscopev1.EventoFluxoRede {
			var evs []*psychoscopev1.EventoFluxoRede
			for i := 0; i < 15; i++ {
				evs = append(evs, synFrom(float64(i), w, "10.0.0.2", uint32(40000+i), 22))
			}
			return evs
		}, "10.0.0.66", "10.0.0.67", NameBruteForce},
		"tunnel": {func(w string) []*psychoscopev1.EventoFluxoRede {
			var evs []*psychoscopev1.EventoFluxoRede
			for i := 0; i < 8; i++ {
				evs = append(evs, dnsQuery(float64(i), "10.0.0.9", randLabel(rng, 48)+".t."+w))
			}
			return evs
		}, "evil-tunnel.com", "other-tunnel.com", NameDNSTunnel},
	} {
		as := run(t, Default(), tc.traffic(tc.who)...)
		if len(as) != 1 || as[0].Regra != tc.rule {
			t.Fatalf("%s: o trafego deveria gerar um alerta de %s: %v", name, tc.rule, names(as))
		}
		field, value, ok := Exception(as[0])
		if !ok {
			t.Fatalf("%s: o alerta deveria ter uma excecao sugerida: %v", name, as[0].Contexto)
		}
		cfg := Default()
		lf := listField(t, &cfg, field)
		lf.Set(reflect.Append(lf, reflect.ValueOf(value)))
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: a excecao sugerida (%s=%q) nao valida: %v", name, field, value, err)
		}
		if got := run(t, cfg, tc.traffic(tc.who)...); len(got) != 0 {
			t.Errorf("%s: com a excecao %s += %q o mesmo trafego nao deve alertar: %v", name, field, value, names(got))
		}
		if got := run(t, cfg, tc.traffic(tc.other)...); len(got) != 1 {
			t.Errorf("%s: um alvo equivalente fora da excecao continua alertando: %v", name, names(got))
		}
	}
}

// Os campos de excecao existem no catalogo e sao listas: se alguem renomear um campo, falha aqui.
func TestExceptionFieldsExistInTheRuleConfig(t *testing.T) {
	c := Default()
	for _, path := range []string{FieldBeaconIgnoreDestinations, FieldBeaconIgnoreDomains, FieldBruteForceIgnoreSources, FieldTunnelAllowedBases} {
		listField(t, &c, path)
	}
}
