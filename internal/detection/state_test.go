package detection

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// memRule e uma regra com estado proprio: conta quantos eventos viu e alerta no primeiro.
type memRule struct {
	gatedRule
	hits int
	key  string // chave de estado (StateKeyed)
}

type memState struct {
	Hits int `json:"hits"`
}

func newMemRule(name string, cooldown time.Duration) *memRule {
	return newKeyedMemRule(name, cooldown, "k")
}

func newKeyedMemRule(name string, cooldown time.Duration, key string) *memRule {
	r := &memRule{key: key}
	r.gatedRule = gatedRule{fnRule{name, func(ev *Event, _ *Window) *psychoscopev1.Alerta {
		r.hits++
		return NewAlert(name, psychoscopev1.Severidade_SEVERIDADE_ALTA, "x", ev, nil)
	}}, cooldown}
	return r
}

func (r *memRule) StateKey() string { return r.key }

func (r *memRule) ExportState(time.Time) any { return memState{Hits: r.hits} }

func (r *memRule) ImportState(raw []byte) (int, error) {
	var st memState
	if err := json.Unmarshal(raw, &st); err != nil {
		return 0, err
	}
	r.hits = st.Hits
	return 1, nil
}

// keyedRule acrescenta uma chave de estado a uma regra Gated.
type keyedRule struct {
	gatedRule
	key string
}

func (k keyedRule) StateKey() string { return k.key }

func countRuleKeyed(name, key string) Rule { return keyedRule{countRule(name).(gatedRule), key} }

func alertsAfter(t *testing.T, pub *recPub, want int) {
	t.Helper()
	eventually(t, "alertas publicados", func() bool { return len(pub.list()) == want })
}

func TestReconfigureKeepsCooldownOfUnchangedRules(t *testing.T) {
	e, pub, stop := startEngine(t, []Rule{countRuleKeyed("r", "k")})
	defer stop()
	submit(e, 0, "a")
	alertsAfter(t, pub, 1)
	reconf(t, e, []Rule{countRuleKeyed("r", "k")}, time.Minute) // mesma chave de estado
	submit(e, 2, "a")
	eventually(t, "evento processado", func() bool { return e.Stats().Processed == 2 })
	if n := len(pub.list()); n != 1 {
		t.Fatalf("o cooldown de uma regra inalterada deve sobreviver a troca: %d alertas", n)
	}
	if e.Stats().Suppressed != 1 {
		t.Fatalf("o segundo evento deveria ser suprimido: %+v", e.Stats())
	}
}

func TestReconfigureNewCooldownAppliesToKeptState(t *testing.T) {
	e, pub, stop := startEngine(t, []Rule{newMemRule("r", time.Hour)})
	defer stop()
	submit(e, 0, "a")
	alertsAfter(t, pub, 1)
	reconf(t, e, []Rule{newMemRule("r", 5*time.Second)}, time.Minute) // so o cooldown mudou: a chave de estado e a mesma
	submit(e, 10, "a")                                                // 10 s depois do alerta: o cooldown novo (5 s) ja venceu
	alertsAfter(t, pub, 2)
}

func TestReconfigureDropsStateOfRemovedRule(t *testing.T) {
	e, pub, stop := startEngine(t, []Rule{countRule("r")})
	defer stop()
	submit(e, 0, "a")
	alertsAfter(t, pub, 1)
	reconf(t, e, []Rule{countRule("outra")}, time.Minute) // r saiu (desligada)
	reconf(t, e, []Rule{countRule("r")}, time.Minute)     // r volta: comeca vazia
	submit(e, 2, "a")
	eventually(t, "regra religada alerta de novo", func() bool { return len(pub.list()) >= 2 })
}

func TestReconfigureCarriesStatefulRuleState(t *testing.T) {
	old := newMemRule("m", time.Hour)
	e, pub, stop := startEngine(t, []Rule{old})
	defer stop()
	submit(e, 0, "a")
	alertsAfter(t, pub, 1)

	kept := newMemRule("m", time.Hour)
	reconf(t, e, []Rule{kept}, time.Minute)
	if kept.hits != 1 {
		t.Fatalf("o estado da regra inalterada passa para a nova instancia: hits=%d", kept.hits)
	}
	changed := newKeyedMemRule("m", time.Hour, "limiar-novo")
	reconf(t, e, []Rule{changed}, time.Minute)
	if changed.hits != 0 {
		t.Fatalf("regra com outra chave de estado comeca vazia: hits=%d", changed.hits)
	}
}

func TestSnapshotRestoreSuppressesRepeatedAlert(t *testing.T) {
	rule := newMemRule("m", time.Hour)
	e, pub, stop := startEngine(t, []Rule{rule})
	submit(e, 0, "a")
	alertsAfter(t, pub, 1)
	snap, err := e.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stop()

	raw, err := json.Marshal(snap) // o que vai para o disco
	if err != nil {
		t.Fatal(err)
	}
	var loaded Snapshot
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("snapshot gravado deve ser lido de volta: %v\n%s", err, raw)
	}

	restored := newMemRule("m", time.Hour)
	pub2 := &recPub{}
	e2 := NewEngine(EngineConfig{Window: time.Minute, QueueSize: 16}, []Rule{restored}, pub2)
	res := e2.Restore(&loaded)
	if res.Cooldowns != 1 || res.Rules["m"] != 1 || restored.hits != 1 {
		t.Fatalf("restauracao: %+v hits=%d", res, restored.hits)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e2.Run(ctx); close(done) }()
	submit(e2, 5, "a") // mesmo cliente, 5 s depois: ainda em cooldown
	eventually(t, "evento processado", func() bool { return e2.Stats().Processed == 1 })
	cancel()
	<-done
	if n := len(pub2.list()); n != 0 || e2.Stats().Suppressed != 1 {
		t.Fatalf("o cooldown restaurado deve suprimir o alerta repetido: alertas=%d %+v", n, e2.Stats())
	}
}

func TestSnapshotKeepsOnlyActiveCooldowns(t *testing.T) {
	e, pub, stop := startEngine(t, []Rule{newMemRule("m", 10*time.Second)})
	submit(e, 0, "a")
	submit(e, 30, "b") // o relogio dos eventos avanca 30 s: o cooldown de "a" ja venceu
	alertsAfter(t, pub, 2)
	snap, err := e.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if len(snap.Cooldowns) != 1 || snap.Cooldowns[0].Chave != "b" {
		t.Fatalf("so o cooldown ativo vai para o snapshot: %+v", snap.Cooldowns)
	}
	if final := e.State(); len(final.Cooldowns) != 1 || final.Versao != SnapshotVersion {
		t.Fatalf("State depois de Run: %+v", final)
	}
}

func TestRestoreIgnoresUnknownRulesBadVersionAndHugeKeys(t *testing.T) {
	rule := newMemRule("m", time.Hour)
	e := NewEngine(EngineConfig{Window: time.Minute}, []Rule{rule}, &recPub{})
	if res := e.Restore(&Snapshot{Versao: SnapshotVersion + 1, Chaves: map[string]string{"m": "k"}, Cooldowns: []CooldownEntry{{Regra: "m", Chave: "a", EmitidoEm: t0}}}); res.Cooldowns != 0 {
		t.Fatalf("versao desconhecida deve ser descartada: %+v", res)
	}
	if res := e.Restore(nil); res.Cooldowns != 0 {
		t.Fatalf("nil: %+v", res)
	}
	res := e.Restore(&Snapshot{Versao: SnapshotVersion, Chaves: map[string]string{"m": "k"}, Cooldowns: []CooldownEntry{
		{Regra: "outra", Chave: "a", EmitidoEm: t0},                   // regra que nao existe
		{Regra: "m", Chave: "", EmitidoEm: t0},                        // chave vazia
		{Regra: "m", Chave: strings.Repeat("k", 5000), EmitidoEm: t0}, // chave gigante
		{Regra: "m", Chave: "ok", EmitidoEm: t0},
	}, Regras: map[string]any{"m": json.RawMessage(`{"hits":"nao e numero"}`), "outra": json.RawMessage(`{}`)}})
	if res.Cooldowns != 1 || res.Rules["m"] != 0 || rule.hits != 0 {
		t.Fatalf("so a entrada valida deve ficar; estado ilegivel deixa a regra vazia: %+v hits=%d", res, rule.hits)
	}
}

func TestSnapshotJSONIsStrict(t *testing.T) {
	var s Snapshot
	if err := json.Unmarshal([]byte(`{"versao":1,"campo_novo":true}`), &s); err == nil {
		t.Fatal("chave desconhecida deve ser erro")
	}
	if err := json.Unmarshal([]byte(`{"versao":1`), &s); err == nil {
		t.Fatal("JSON truncado deve ser erro")
	}
	if err := json.Unmarshal([]byte(`{"versao":1,"regras":{"m":{"hits":9007199254740993}}}`), &s); err != nil {
		t.Fatal(err)
	}
	if got := string(s.Regras["m"].(json.RawMessage)); !strings.Contains(got, "9007199254740993") {
		t.Fatalf("inteiros grandes nao podem passar por float64: %s", got)
	}
}

func TestSnapshotUnderLoadIsRaceFree(t *testing.T) {
	e, _, stop := startEngine(t, []Rule{newMemRule("m", time.Hour)})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			if _, err := e.Snapshot(context.Background()); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 500; i++ {
		submit(e, float64(i)*0.01, "a")
	}
	<-done
	stop()
}

// Estado salvo com outra chave de estado (limiar ajustado no arquivo de configuracao entre duas
// partidas), ou de um snapshot sem chaves, nao vale: a regra comeca vazia.
func TestRestoreDropsStateOfRuleWithAnotherStateKey(t *testing.T) {
	saved := &Snapshot{Versao: SnapshotVersion, Chaves: map[string]string{"m": "limiar-antigo"},
		Cooldowns: []CooldownEntry{{Regra: "m", Chave: "a", EmitidoEm: t0}},
		Regras:    map[string]any{"m": json.RawMessage(`{"hits":7}`)}}
	for name, snap := range map[string]*Snapshot{
		"chave diferente": saved,
		"sem chaves":      {Versao: SnapshotVersion, Cooldowns: saved.Cooldowns, Regras: saved.Regras},
	} {
		rule := newKeyedMemRule("m", time.Hour, "limiar-novo")
		e := NewEngine(EngineConfig{Window: time.Minute}, []Rule{rule}, &recPub{})
		if res := e.Restore(snap); res.Cooldowns != 0 || len(res.Rules) != 0 || rule.hits != 0 {
			t.Errorf("%s: o estado nao deve ser restaurado: %+v hits=%d", name, res, rule.hits)
		}
	}
	rule := newKeyedMemRule("m", time.Hour, "limiar-antigo")
	e := NewEngine(EngineConfig{Window: time.Minute}, []Rule{rule}, &recPub{})
	if res := e.Restore(saved); res.Cooldowns != 1 || rule.hits != 7 {
		t.Errorf("controle: com a mesma chave o estado volta: %+v hits=%d", res, rule.hits)
	}
}

func TestSnapshotRecordsTheStateKeys(t *testing.T) {
	e := NewEngine(EngineConfig{Window: time.Minute}, []Rule{newKeyedMemRule("m", time.Hour, "abc"), countRule("sem-chave")}, &recPub{})
	snap := e.State()
	if snap.Chaves["m"] != "abc" || len(snap.Chaves) != 1 {
		t.Fatalf("so as regras StateKeyed entram em Chaves: %v", snap.Chaves)
	}
}
