package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
)

// feedBeats entrega ao beacon n batidas regulares (a cada 30 s a partir de start) e conta os alertas.
func feedBeats(b *Beacon, start float64, n int) (alerts int) {
	for i := 0; i < n; i++ {
		ev := detection.NewEvent("m", synFrom(start+float64(i)*30, "10.0.0.5", "203.0.113.7", uint32(50000+i), 443), time.Now())
		if b.Eval(ev, nil) != nil {
			alerts++
		}
	}
	return alerts
}

func exportJSON(t *testing.T, b *Beacon, now time.Time) []byte {
	t.Helper()
	raw, err := json.Marshal(b.ExportState(now))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newBeaconWith(t *testing.T, cfg BeaconConfig, raw []byte) (*Beacon, int) {
	t.Helper()
	b := NewBeacon(cfg)
	n, err := b.ImportState(raw)
	if err != nil {
		t.Fatalf("ImportState: %v", err)
	}
	return b, n
}

func TestBeaconStateKeepsPartialSeriesAcrossRestart(t *testing.T) {
	cfg := Default().Beacon
	first := NewBeacon(cfg)
	if n := feedBeats(first, 0, 7); n != 0 { // 7 contatos: ainda abaixo do minimo de 8
		t.Fatalf("nao deveria alertar com 7 contatos: %d", n)
	}
	raw := exportJSON(t, first, tm(210))

	restored, kept := newBeaconWith(t, cfg, raw)
	if kept != 1 {
		t.Fatalf("a serie deveria ser restaurada: kept=%d", kept)
	}
	if n := feedBeats(restored, 210, 1); n != 1 { // o 8o contato fecha a serie
		t.Fatalf("a serie restaurada deve completar o beacon: %d alertas", n)
	}
	if n := feedBeats(NewBeacon(cfg), 210, 1); n != 0 { // sem restaurar, um contato sozinho nao alerta
		t.Fatalf("controle: sem estado nao pode alertar: %d", n)
	}
}

func TestBeaconStateKeepsCooldownAcrossRestart(t *testing.T) {
	cfg := Default().Beacon
	first := NewBeacon(cfg)
	if n := feedBeats(first, 0, 8); n != 1 {
		t.Fatalf("esperado o alerta inicial: %d", n)
	}
	raw := exportJSON(t, first, tm(210))

	restored, kept := newBeaconWith(t, cfg, raw)
	if kept != 2 { // a serie e o cooldown
		t.Fatalf("kept=%d", kept)
	}
	if n := feedBeats(restored, 240, 20); n != 0 { // 10 min de batidas, dentro do cooldown de 30 min
		t.Fatalf("o cooldown restaurado deve suprimir o alerta repetido: %d", n)
	}
	// controle: sem o estado, o mesmo trafego alertaria de novo
	if n := feedBeats(NewBeacon(cfg), 240, 20); n != 1 {
		t.Fatalf("controle: sem estado o beacon alerta de novo: %d", n)
	}
}

func TestBeaconStateNewCooldownAppliesToSavedAlert(t *testing.T) {
	cfg := Default().Beacon
	first := NewBeacon(cfg)
	feedBeats(first, 0, 8)
	raw := exportJSON(t, first, tm(210))

	shorter := cfg
	shorter.Cooldown = time.Minute
	restored, _ := newBeaconWith(t, shorter, raw)
	// as batidas seguem a cada 30 s (240, 270, 300): o alerta foi aos 210 s, e o cooldown novo
	// (1 min) vence aos 270 s, enquanto o antigo (30 min) ainda suprimiria
	if n := feedBeats(restored, 240, 3); n != 1 {
		t.Fatalf("o cooldown atual da regra vale sobre o instante salvo: %d", n)
	}
	same, _ := newBeaconWith(t, cfg, raw)
	if n := feedBeats(same, 240, 3); n != 0 {
		t.Fatalf("controle: com o cooldown antigo nada alerta: %d", n)
	}
}

func TestBeaconStateMinIntervalChangeDropsSeriesKeepsCooldown(t *testing.T) {
	cfg := Default().Beacon
	first := NewBeacon(cfg)
	feedBeats(first, 0, 8)
	raw := exportJSON(t, first, tm(210))

	changed := cfg
	changed.MinInterval = 10 * time.Second
	_, kept := newBeaconWith(t, changed, raw)
	if kept != 1 {
		t.Fatalf("com outro min_interval so o cooldown fica: kept=%d", kept)
	}
}

func TestBeaconStateTrimsToMaxKeysKeepingNewest(t *testing.T) {
	cfg := Default().Beacon
	big := NewBeacon(cfg)
	for i := 0; i < 5; i++ { // cinco series, a i-esima vista em i*100 s
		ev := detection.NewEvent("m", synFrom(float64(i)*100, fmt.Sprintf("10.0.0.%d", i), "203.0.113.7", 50000, 443), time.Now())
		big.Eval(ev, nil)
	}
	raw := exportJSON(t, big, tm(500))

	small := cfg
	small.MaxKeys = 2
	b, kept := newBeaconWith(t, small, raw)
	if kept != 2 || len(b.series) != 2 {
		t.Fatalf("deve aparar para max_keys: kept=%d series=%d", kept, len(b.series))
	}
	for _, want := range []string{"tcp|10.0.0.4|203.0.113.7:443", "tcp|10.0.0.3|203.0.113.7:443"} {
		if b.series[want] == nil {
			t.Errorf("deveria ter ficado a serie mais recente %s", want)
		}
	}
}

func TestBeaconExportSkipsStaleSeriesAndExpiredCooldowns(t *testing.T) {
	cfg := Default().Beacon
	b := NewBeacon(cfg)
	feedBeats(b, 0, 8) // alerta aos 210 s; cooldown de 30 min
	if st := b.ExportState(tm(300)).(beaconState); len(st.Series) != 1 || len(st.Cooldowns) != 1 {
		t.Fatalf("logo depois do alerta tudo e util: %+v", st)
	}
	later := tm(210).Add(3 * time.Hour) // passou do cooldown e de 2x max_interval (2 h)
	if st := b.ExportState(later).(beaconState); len(st.Series) != 0 || len(st.Cooldowns) != 0 {
		t.Fatalf("serie parada e cooldown vencido nao devem ser exportados: %+v", st)
	}
}

func TestBeaconImportRejectsHostileState(t *testing.T) {
	cfg := Default().Beacon
	min := int64(cfg.MinInterval)
	ts := func(sec int) int64 { return tm(float64(sec)).UnixNano() }
	manyContacts := strings.TrimSuffix(strings.Repeat(fmt.Sprintf("%d,", ts(1)), maxSeriesLen+1), ",")
	cases := []struct {
		name, raw string
		kept      int
		wantErr   bool
	}{
		{"chave de outro tipo", fmt.Sprintf(`{"min_interval_ns":%d,"series":[{"chave":"udp|a|b","visto_ns":%d,"contatos_ns":[%d]}]}`, min, ts(1), ts(1)), 0, false},
		{"chave gigante", fmt.Sprintf(`{"min_interval_ns":%d,"series":[{"chave":"tcp|%s","visto_ns":%d,"contatos_ns":[%d]}]}`, min, strings.Repeat("x", 5000), ts(1), ts(1)), 0, false},
		{"sem contatos", fmt.Sprintf(`{"min_interval_ns":%d,"series":[{"chave":"tcp|a|b","visto_ns":%d,"contatos_ns":[]}]}`, min, ts(1)), 0, false},
		{"contatos demais", fmt.Sprintf(`{"min_interval_ns":%d,"series":[{"chave":"tcp|a|b","visto_ns":%d,"contatos_ns":[%s]}]}`, min, ts(1), manyContacts), 0, false},
		{"fora de ordem", fmt.Sprintf(`{"min_interval_ns":%d,"series":[{"chave":"tcp|a|b","visto_ns":%d,"contatos_ns":[%d,%d]}]}`, min, ts(9), ts(5), ts(2)), 0, false},
		{"contato depois do visto", fmt.Sprintf(`{"min_interval_ns":%d,"series":[{"chave":"tcp|a|b","visto_ns":%d,"contatos_ns":[%d]}]}`, min, ts(1), ts(5)), 0, false},
		{"cooldown sem instante", fmt.Sprintf(`{"min_interval_ns":%d,"cooldowns":[{"chave":"tcp|a|b","alerta_ns":0}]}`, min), 0, false},
		{"entrada valida", fmt.Sprintf(`{"min_interval_ns":%d,"series":[{"chave":"dns|a|x.example","visto_ns":%d,"contatos_ns":[%d,%d]}]}`, min, ts(9), ts(2), ts(9)), 1, false},
		{"campo desconhecido", `{"min_interval_ns":1,"extra":true}`, 0, true},
		{"truncado", `{"min_interval_ns":`, 0, true},
		{"tipo errado", `{"min_interval_ns":"x"}`, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := NewBeacon(cfg)
			n, err := b.ImportState([]byte(c.raw))
			if (err != nil) != c.wantErr || n != c.kept || len(b.series)+len(b.cooldown) != c.kept {
				t.Fatalf("kept=%d err=%v series=%d cooldowns=%d", n, err, len(b.series), len(b.cooldown))
			}
		})
	}
}

func stateKeys(t *testing.T, c Config) map[string]string {
	t.Helper()
	rs, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rs {
		k, ok := r.(detection.StateKeyed)
		if !ok {
			t.Fatalf("a regra %s deve implementar detection.StateKeyed", r.Name())
		}
		out[r.Name()] = k.StateKey()
	}
	return out
}

func TestStateKeyChangesOnlyWithStateAffectingFields(t *testing.T) {
	base := stateKeys(t, Default())
	if len(base) != len(AllNames()) {
		t.Fatalf("toda regra tem chave de estado: %d de %d", len(base), len(AllNames()))
	}
	edit := func(f func(*Config)) map[string]string { c := Default(); f(&c); return stateKeys(t, c) }
	changed := func(next map[string]string) []string {
		var out []string
		for _, n := range AllNames() {
			if k, built := next[n]; built && k != base[n] { // regra desligada nao e "mudada"
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	cases := []struct {
		name string
		next map[string]string
		want []string
	}{
		{"igual", edit(func(*Config) {}), nil},
		{"um limiar", edit(func(c *Config) { c.Beacon.MaxCV = 0.1 }), []string{NameBeacon}},
		{"min_interval", edit(func(c *Config) { c.Beacon.MinInterval = 10 * time.Second }), []string{NameBeacon}},
		{"duas regras", edit(func(c *Config) { c.Scan.VerticalPorts = 5; c.ICMPSweep.MinHosts = 5 }), []string{NameICMPSweep, NameScanSYN}},
		{"cooldown nao muda a chave", edit(func(c *Config) { c.Beacon.Cooldown = time.Minute; c.Scan.Cooldown = time.Hour }), nil},
		{"lista de excecao nao muda a chave", edit(func(c *Config) {
			c.Beacon.IgnoreDestinations = []string{"203.0.113.0/24"}
			c.Beacon.IgnoreDomains = []string{"example.com"}
			c.Tunnel.AllowedBases = []string{"cdn.example"}
			c.BruteForce.IgnoreSources = []string{"10.9.0.0/16"}
			c.TLS.AllowedBases = []string{"cdn.example"}
			c.NXDomain.IgnoreSuffixes = []string{"corp.example"}
		}), nil},
		{"tetos nao mudam a chave", edit(func(c *Config) { c.Beacon.MaxKeys = 100; c.Scan.MaxScan = 10 }), nil},
		{"so a lista de desligadas", edit(func(c *Config) { c.Disabled = []string{NameDNSRate} }), nil},
		{"lista nula e vazia sao iguais", edit(func(c *Config) { c.Beacon.IgnorePorts = []int{}; c.Tunnel.AllowedBases = []string{} }), nil},
	}
	for _, c := range cases {
		sort.Strings(c.want)
		if got := changed(c.next); fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: mudaram %v, esperado %v", c.name, got, c.want)
		}
	}
}

// BenchmarkBeaconExportState mede o que ExportState ocupa a goroutine do motor com o teto
// padrao de series (50 mil); a codificacao em JSON fica fora dela.
func BenchmarkBeaconExportState(b *testing.B) {
	cfg := Default().Beacon
	r := NewBeacon(cfg)
	for i := 0; i < cfg.MaxKeys; i++ {
		s := &series{seen: tm(1000)}
		for k := 0; k < maxSeriesLen; k++ {
			s.times = append(s.times, tm(float64(k)*30))
		}
		r.series[fmt.Sprintf("tcp|10.%d.%d.%d|203.0.113.7:443", i>>16&255, i>>8&255, i&255)] = s
		r.cooldown[fmt.Sprintf("tcp|10.%d.%d.%d|203.0.113.7:443", i>>16&255, i>>8&255, i&255)] = tm(990)
	}
	now := tm(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.ExportState(now)
	}
}

// tm e o instante t0+sec, como time.Time (at devolve o timestamp do proto).
func tm(sec float64) time.Time { return at(sec).AsTime() }
