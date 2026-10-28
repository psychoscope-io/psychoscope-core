package rules

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Motivos de net.tls.suspicious, em ordem de prioridade quando um evento tem mais de um.
const (
	tlsIPLiteral  = "sni_ip_literal"
	tlsEntropy    = "sni_alta_entropia"
	tlsObsolete   = "versao_obsoleta"
	tlsMissingSNI = "sni_ausente"
)

// TLSSuspicious inspeciona ClientHellos: SNI que e um IP literal (MEDIA; o RFC 6066 proibe),
// SNI com rotulo longo e de alta entropia (MEDIA; DGA sobre HTTPS), versao maxima oferecida
// obsoleta — SSL3/TLS1.0/TLS1.1 (BAIXA) — e ClientHellos repetidos sem SNI (BAIXA).
// A versao e a MAIOR oferecida pelo cliente, nao a negociada.
type TLSSuspicious struct {
	cfg     TLSConfig
	allowed []string // allowed_bases normalizados (minusculos, sem ponto)
}

func NewTLSSuspicious(cfg TLSConfig) *TLSSuspicious {
	return &TLSSuspicious{cfg: cfg, allowed: normalizeDomains(cfg.AllowedBases)}
}

func (r *TLSSuspicious) Name() string            { return NameTLSSuspicious }
func (r *TLSSuspicious) Cooldown() time.Duration { return r.cfg.Cooldown }

// classify devolve o motivo de maior prioridade para o evento TLS ("" = nada suspeito).
func (r *TLSSuspicious) classify(ev *detection.Event) string {
	t := ev.TLS()
	if t == nil {
		return ""
	}
	sni := strings.ToLower(t.SniHostname)
	switch {
	case sni != "" && isIPLiteral(sni):
		return tlsIPLiteral
	case sni != "" && r.highEntropy(sni):
		return tlsEntropy
	case t.VersaoTls == "SSL3.0" || t.VersaoTls == "TLS1.0" || t.VersaoTls == "TLS1.1":
		return tlsObsolete
	case sni == "":
		return tlsMissingSNI
	}
	return ""
}

func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

// highEntropy: algum rotulo do SNI (exceto o TLD) e longo e aleatorio e o SNI nao esta sob
// nenhum allowed_bases.
func (r *TLSSuspicious) highEntropy(sni string) bool {
	// Por sufixo: "windows.net" isenta tudo sob ele, e "blob.core.windows.net" so o armazenamento
	// (a lista antiga, de dominios base, continua valendo: o base e um sufixo do SNI).
	if hasDomainSuffix(sni, r.allowed) {
		return false
	}
	labels := strings.Split(sni, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels[:len(labels)-1] {
		// Rotulos com hifen sao quase sempre nomes legiveis ("internal-service-gateway" tem
		// entropia de rotulo aleatorio); DGA/ids gerados costumam ser alfanumericos puros.
		if len(l) >= r.cfg.MinLabelLen && !strings.Contains(l, "-") && entropy(l) >= r.cfg.MinEntropy {
			return true
		}
	}
	return false
}

func (r *TLSSuspicious) Key(ev *detection.Event) (string, bool) {
	reason := r.classify(ev)
	if reason == "" || ev.Net.IpOrigem == "" {
		return "", false
	}
	return ev.Net.IpOrigem + "|" + reason, true
}

func (r *TLSSuspicious) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	reason := r.classify(ev)
	t := ev.TLS()
	client := ev.Net.IpOrigem
	ctx := map[string]string{
		"motivo": reason, "cliente": client, "destino": ev.Net.IpDestino,
		"sni": t.SniHostname, "versao_tls": t.VersaoTls,
	}

	switch reason {
	case tlsIPLiteral:
		return detection.NewAlert(NameTLSSuspicious, psychoscopev1.Severidade_SEVERIDADE_MEDIA,
			fmt.Sprintf("TLS com SNI igual a um IP (%s): %s -> %s", t.SniHostname, client, ev.Net.IpDestino), ev, ctx)
	case tlsEntropy:
		return detection.NewAlert(NameTLSSuspicious, psychoscopev1.Severidade_SEVERIDADE_MEDIA,
			fmt.Sprintf("SNI com rotulo longo e aleatorio (possivel DGA): %s -> %s", t.SniHostname, client), ev, ctx)
	case tlsObsolete:
		return detection.NewAlert(NameTLSSuspicious, psychoscopev1.Severidade_SEVERIDADE_BAIXA,
			fmt.Sprintf("Cliente %s oferece no maximo %s para %s", client, t.VersaoTls, ev.Net.IpDestino), ev, ctx)
	case tlsMissingSNI:
		evs := w.FromSrc(client)
		if len(evs) < r.cfg.MissingSNIMin {
			return nil
		}
		cutoff := ev.At.Add(-r.cfg.MissingSNIWindow)
		n := 0
		for i := len(evs) - 1; i >= 0 && !evs[i].At.Before(cutoff); i-- {
			if tt := evs[i].TLS(); tt != nil && tt.SniHostname == "" {
				n++
			}
		}
		if n < r.cfg.MissingSNIMin {
			return nil
		}
		ctx["ocorrencias"] = fmt.Sprint(n)
		ctx["janela"] = r.cfg.MissingSNIWindow.String()
		return detection.NewAlert(NameTLSSuspicious, psychoscopev1.Severidade_SEVERIDADE_BAIXA,
			fmt.Sprintf("%s fez %d ClientHellos sem SNI em %s", client, n, r.cfg.MissingSNIWindow), ev, ctx)
	}
	return nil
}
