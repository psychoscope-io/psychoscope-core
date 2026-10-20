package detection

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Rule e uma regra analitica. Eval e chamada para cada evento DEPOIS de ele entrar na
// janela e devolve um alerta, ou nil. Deve ser rapida e nao pode reter `w` nem as
// fatias que ele devolve.
type Rule interface {
	Name() string
	Eval(ev *Event, w *Window) *psychoscopev1.Alerta
}

// Gated e implementada por regras que querem pre-filtro barato e supressao de repeticoes.
// O motor so chama Eval se Key reportar ok=true e a chave nao estiver em cooldown
// (tempo dos eventos); apos um alerta, a chave fica suprimida por Cooldown().
type Gated interface {
	Rule
	Key(ev *Event) (key string, ok bool)
	Cooldown() time.Duration
}

// NewAlert monta um alerta da regra com os campos comuns preenchidos.
// ctx e copiado; "chave" e "evento_ts" sao adicionados ao contexto.
func NewAlert(rule string, sev psychoscopev1.Severidade, desc string, ev *Event, ctx map[string]string) *psychoscopev1.Alerta {
	c := make(map[string]string, len(ctx)+2)
	for k, v := range ctx {
		c[k] = v
	}
	c["evento_ts"] = ev.At.UTC().Format(time.RFC3339Nano)
	return &psychoscopev1.Alerta{
		Regra: rule, Severidade: sev, Descricao: desc,
		IdModuloOrigem: ev.Module, Contexto: c,
	}
}

func newAlertID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
