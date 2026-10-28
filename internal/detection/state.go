package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// SnapshotVersion e a versao do formato de Snapshot; quem le um valor diferente descarta o estado.
const SnapshotVersion = 1

// Stateful e implementada por regras com estado proprio que deve sobreviver a um reinicio ou a
// um Reconfigure (como as series do net.beacon). Os dois metodos so sao chamados pela goroutine
// do motor, ou antes de Run / depois de Run retornar.
type Stateful interface {
	Rule
	// ExportState devolve uma copia independente do estado ainda util em now (tempo dos
	// eventos), pronta para ser codificada em JSON fora da goroutine do motor.
	ExportState(now time.Time) any
	// ImportState restaura o estado gerado por ExportState (ja codificado em JSON). Descarta
	// o que for invalido ou incompativel com a configuracao atual e devolve quantas entradas
	// ficaram; em erro a regra continua como estava.
	ImportState(raw []byte) (kept int, err error)
}

// CooldownEntry e um cooldown do motor: o instante (tempo dos eventos) do ultimo alerta da
// chave. O prazo vem do cooldown atual da regra, entao mudar o cooldown vale sobre o estado salvo.
type CooldownEntry struct {
	Regra     string    `json:"regra"`
	Chave     string    `json:"chave"`
	EmitidoEm time.Time `json:"emitido_em"`
}

// Snapshot e o estado do motor que sobrevive a um reinicio. SalvoEm (relogio de parede) e
// preenchido por quem grava; o motor nao le o relogio do sistema.
type Snapshot struct {
	Versao    int             `json:"versao"`
	SalvoEm   time.Time       `json:"salvo_em"`
	Cooldowns []CooldownEntry `json:"cooldowns,omitempty"`
	// Regras guarda o estado de cada regra Stateful por nome. Ao exportar, os valores sao as
	// copias de ExportState; ao ler de um arquivo, json.RawMessage.
	Regras map[string]any `json:"regras,omitempty"`
}

// UnmarshalJSON le um Snapshot de um arquivo: chaves desconhecidas sao erro, e o estado de cada
// regra fica como json.RawMessage (sem passar por float64, que perderia precisao de inteiros).
func (s *Snapshot) UnmarshalJSON(b []byte) error {
	var aux struct {
		Versao    int                        `json:"versao"`
		SalvoEm   time.Time                  `json:"salvo_em"`
		Cooldowns []CooldownEntry            `json:"cooldowns"`
		Regras    map[string]json.RawMessage `json:"regras"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&aux); err != nil {
		return err
	}
	*s = Snapshot{Versao: aux.Versao, SalvoEm: aux.SalvoEm, Cooldowns: aux.Cooldowns}
	if len(aux.Regras) > 0 {
		s.Regras = make(map[string]any, len(aux.Regras))
		for name, raw := range aux.Regras {
			s.Regras[name] = raw
		}
	}
	return nil
}

// snapshotRequest e um pedido de Snapshot, atendido dentro de Run.
type snapshotRequest struct{ reply chan *Snapshot }

// Snapshot devolve uma copia do estado do motor. O pedido e atendido na goroutine do motor
// (dona do estado), que so copia: a codificacao e a escrita ficam com quem chama. ctx limita
// so a entrega do pedido; erro de contexto diz que nada foi copiado.
func (e *Engine) Snapshot(ctx context.Context) (*Snapshot, error) {
	req := snapshotRequest{reply: make(chan *Snapshot, 1)}
	select {
	case e.snap <- req:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return <-req.reply, nil
}

// State devolve o estado final do motor. So pode ser chamado depois que Run retornou (a
// goroutine do motor ja nao existe, entao nada corre com a leitura).
func (e *Engine) State() *Snapshot { return e.snapshot() }

// snapshot copia cooldowns ainda ativos e o estado das regras Stateful.
func (e *Engine) snapshot() *Snapshot {
	now := e.window.Now()
	s := &Snapshot{Versao: SnapshotVersion}
	cooldowns := e.gatedCooldowns()
	for k, last := range e.cooldown {
		if d, ok := cooldowns[k.rule]; ok && now.Before(last.Add(d)) {
			s.Cooldowns = append(s.Cooldowns, CooldownEntry{Regra: k.rule, Chave: k.key, EmitidoEm: last.UTC()})
		}
	}
	slices.SortFunc(s.Cooldowns, func(a, b CooldownEntry) int {
		return compareStrings(a.Regra+"\x00"+a.Chave, b.Regra+"\x00"+b.Chave)
	})
	for _, r := range e.rules {
		if st, ok := r.(Stateful); ok {
			if s.Regras == nil {
				s.Regras = map[string]any{}
			}
			s.Regras[r.Name()] = st.ExportState(now)
		}
	}
	return s
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// gatedCooldowns devolve o cooldown atual de cada regra Gated, por nome.
func (e *Engine) gatedCooldowns() map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, r := range e.rules {
		if g, ok := r.(Gated); ok {
			out[r.Name()] = g.Cooldown()
		}
	}
	return out
}

// RestoreResult resume o que Restore aproveitou.
type RestoreResult struct {
	Cooldowns int            // cooldowns do motor restaurados
	Rules     map[string]int // entradas restauradas por regra Stateful
}

// maxCooldownKeyLen limita a chave de um cooldown restaurado (entrada nao confiavel).
const maxCooldownKeyLen = 512

// Restore carrega o estado salvo. So pode ser chamado antes de Run. Regras desconhecidas,
// desligadas ou sem estado sao ignoradas, e uma regra cujo estado nao pode ser lido comeca vazia.
func (e *Engine) Restore(s *Snapshot) RestoreResult {
	res := RestoreResult{Rules: map[string]int{}}
	if s == nil || s.Versao != SnapshotVersion {
		return res
	}
	cooldowns := e.gatedCooldowns()
	for _, c := range s.Cooldowns {
		if _, ok := cooldowns[c.Regra]; ok && c.Chave != "" && len(c.Chave) <= maxCooldownKeyLen {
			e.cooldown[cooldownKey{c.Regra, c.Chave}] = c.EmitidoEm
			res.Cooldowns++
		}
	}
	for _, r := range e.rules {
		st, ok := r.(Stateful)
		if !ok || s.Regras[r.Name()] == nil {
			continue
		}
		if n, err := importRuleState(st, s.Regras[r.Name()]); err != nil {
			e.log.Warn("estado da regra descartado", "regra", r.Name(), "erro", err.Error())
		} else {
			res.Rules[r.Name()] = n
		}
	}
	return res
}

// importRuleState entrega a uma regra o estado exportado (copia em memoria ou JSON lido).
func importRuleState(st Stateful, v any) (int, error) {
	raw, ok := v.(json.RawMessage)
	if !ok {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			return 0, fmt.Errorf("codificar o estado: %w", err)
		}
	}
	return st.ImportState(raw)
}

// carryState leva ao conjunto novo o estado das regras que continuam com a mesma configuracao
// (as de fresh, e as que saem, comecam vazias): cooldowns do motor e estado das Stateful.
// Roda dentro de Run, antes de e.rules ser trocada.
func (e *Engine) carryState(next []Rule, fresh []string) {
	keep := map[string]bool{}
	for _, r := range next {
		if _, ok := r.(Gated); ok && !slices.Contains(fresh, r.Name()) {
			keep[r.Name()] = true
		}
	}
	for k := range e.cooldown {
		if !keep[k.rule] {
			delete(e.cooldown, k)
		}
	}
	old := map[string]Stateful{}
	for _, r := range e.rules {
		if st, ok := r.(Stateful); ok {
			old[r.Name()] = st
		}
	}
	now := e.window.Now()
	for _, r := range next {
		st, ok := r.(Stateful)
		prev := old[r.Name()]
		if !ok || prev == nil || slices.Contains(fresh, r.Name()) {
			continue
		}
		if _, err := importRuleState(st, prev.ExportState(now)); err != nil {
			e.log.Warn("estado da regra nao foi levado na troca", "regra", r.Name(), "erro", err.Error())
		}
	}
}
