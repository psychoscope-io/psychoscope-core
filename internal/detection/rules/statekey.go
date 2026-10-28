package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
)

// stateKey resume os campos de cfg que mudam o significado do estado ja acumulado pela regra
// (cooldowns e, no beacon, as series): limiares e janelas. Ficam de fora os campos marcados com
// a tag `keepstate` (cooldown e tetos, que o estado salvo absorve porque guarda o instante do
// alerta, e listas de excecao, que so filtram o que entra). Dois valores iguais de stateKey
// significam que o estado de uma configuracao serve a outra; a diferenca faz a regra recomecar
// vazia, para o alerta voltar a aparecer depois de um ajuste. Listas vazias e nulas contam como iguais.
func stateKey(cfg any) string {
	v := reflect.ValueOf(cfg)
	t := v.Type()
	h := sha256.New()
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get("keepstate") != "" {
			continue
		}
		fmt.Fprintf(h, "%s=%v;", t.Field(i).Name, v.Field(i).Interface())
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// As oito regras implementam detection.StateKeyed (um teste cobra toda regra nova).

func (r *ScanSYN) StateKey() string       { return stateKey(r.cfg) }
func (r *NXDomainBurst) StateKey() string { return stateKey(r.cfg) }
func (r *DNSTunnel) StateKey() string     { return stateKey(r.cfg) }
func (r *DNSRate) StateKey() string       { return stateKey(r.cfg) }
func (r *TLSSuspicious) StateKey() string { return stateKey(r.cfg) }
func (r *Beacon) StateKey() string        { return stateKey(r.cfg) }
func (r *BruteForce) StateKey() string    { return stateKey(r.cfg) }
func (r *ICMPSweep) StateKey() string     { return stateKey(r.cfg) }
