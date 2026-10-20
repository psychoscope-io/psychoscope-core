package rules

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Bandeira27/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
)

const rcodeNXDomain = 3

// ---- net.dns.nxdomain_burst ----

// NXDomainBurst detecta clientes que recebem muitas respostas NXDOMAIN para dominios
// distintos em pouco tempo — padrao tipico de malware com DGA procurando seu C2 (MEDIA).
type NXDomainBurst struct{ cfg NXDomainConfig }

func NewNXDomainBurst(cfg NXDomainConfig) *NXDomainBurst { return &NXDomainBurst{cfg} }

func (r *NXDomainBurst) Name() string            { return NameDNSNXDomain }
func (r *NXDomainBurst) Cooldown() time.Duration { return r.cfg.Cooldown }

func isNX(ev *detection.Event) bool {
	d := ev.DNS()
	return d != nil && d.EhResposta && d.CodigoResposta == rcodeNXDomain
}

// Key: o cliente e o destino da resposta.
func (r *NXDomainBurst) Key(ev *detection.Event) (string, bool) {
	if !isNX(ev) || ev.Net.IpDestino == "" {
		return "", false
	}
	return ev.Net.IpDestino, true
}

func (r *NXDomainBurst) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	client := ev.Net.IpDestino
	cutoff := ev.At.Add(-r.cfg.Window)
	evs := w.ToDst(client)
	count := 0
	domains := map[string]struct{}{}
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		if e.At.Before(cutoff) {
			break
		}
		if isNX(e) {
			count++
			domains[e.DNS().DominioConsultado] = struct{}{}
		}
	}
	if count < r.cfg.MinResponses || len(domains) < r.cfg.MinDistinct {
		return nil
	}
	names := make([]string, 0, len(domains))
	for d := range domains {
		names = append(names, d)
	}
	sort.Strings(names)
	if len(names) > 5 {
		names = names[:5]
	}
	return detection.NewAlert(NameDNSNXDomain, psychoscopev1.Severidade_SEVERIDADE_MEDIA,
		fmt.Sprintf("Rajada de NXDOMAIN (possivel DGA): %s recebeu %d respostas para %d dominios distintos em %s", client, count, len(domains), r.cfg.Window),
		ev, map[string]string{
			"cliente": client, "resolvedor": ev.Net.IpOrigem, "respostas_nxdomain": fmt.Sprint(count),
			"dominios_distintos": fmt.Sprint(len(domains)), "janela": r.cfg.Window.String(), "dominios_exemplo": strings.Join(names, ","),
		})
}

// ---- net.dns.tunnel ----

// DNSTunnel detecta tuneis/exfiltracao via DNS: varias consultas, ao mesmo dominio base,
// com subdominios longos e de alta entropia (dados codificados) (ALTA).
// Falsos positivos conhecidos: CDNs/servicos que usam hashes longos — use AllowedBases.
type DNSTunnel struct{ cfg TunnelConfig }

func NewDNSTunnel(cfg TunnelConfig) *DNSTunnel { return &DNSTunnel{cfg} }

func (r *DNSTunnel) Name() string            { return NameDNSTunnel }
func (r *DNSTunnel) Cooldown() time.Duration { return r.cfg.Cooldown }

func (r *DNSTunnel) suspicious(domain string) (base string, ok bool) {
	base, sub := splitDomain(domain)
	if sub == "" || base == "" || strings.HasSuffix(base, ".arpa") || strings.HasSuffix(base, ".local") ||
		slices.Contains(r.cfg.AllowedBases, base) {
		return "", false
	}
	for _, label := range strings.Split(sub, ".") {
		if len(label) >= r.cfg.MinLabelLen && entropy(label) >= r.cfg.MinEntropy {
			return base, true
		}
	}
	return "", false
}

func (r *DNSTunnel) Key(ev *detection.Event) (string, bool) {
	d := ev.DNS()
	if d == nil || d.EhResposta || ev.Net.IpOrigem == "" {
		return "", false
	}
	base, ok := r.suspicious(d.DominioConsultado)
	if !ok {
		return "", false
	}
	return ev.Net.IpOrigem + "|" + base, true
}

func (r *DNSTunnel) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	client := ev.Net.IpOrigem
	base, _ := r.suspicious(ev.DNS().DominioConsultado)
	cutoff := ev.At.Add(-r.cfg.Window)
	evs := w.FromSrc(client)
	seen := map[string]struct{}{}
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		if e.At.Before(cutoff) {
			break
		}
		d := e.DNS()
		if d == nil || d.EhResposta {
			continue
		}
		if b, ok := r.suspicious(d.DominioConsultado); ok && b == base {
			seen[d.DominioConsultado] = struct{}{}
		}
	}
	if len(seen) < r.cfg.MinQueries {
		return nil
	}
	example := ev.DNS().DominioConsultado
	if len(example) > 80 {
		example = example[:80] + "..."
	}
	return detection.NewAlert(NameDNSTunnel, psychoscopev1.Severidade_SEVERIDADE_ALTA,
		fmt.Sprintf("Possivel tunel DNS: %s fez %d consultas distintas com subdominios longos/aleatorios sob %s em %s", client, len(seen), base, r.cfg.Window),
		ev, map[string]string{
			"cliente": client, "dominio_base": base, "consultas_distintas": fmt.Sprint(len(seen)),
			"janela": r.cfg.Window.String(), "consulta_exemplo": example,
		})
}

// ---- utilitarios ----

// Sufixos de dois niveis comuns, para que "x.co.uk" tenha base "x.co.uk" e nao "co.uk".
var twoLevelSuffixes = []string{
	"co.uk", "org.uk", "ac.uk", "gov.uk", "com.br", "org.br", "net.br", "gov.br", "edu.br",
	"com.au", "net.au", "org.au", "co.jp", "co.nz", "co.za", "com.mx", "com.ar", "com.cn", "com.tr",
}

// splitDomain separa o dominio em (base registravel, subdominio).
func splitDomain(domain string) (base, sub string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	labels := strings.Split(domain, ".")
	n := 2
	if len(labels) >= 2 && slices.Contains(twoLevelSuffixes, strings.Join(labels[len(labels)-2:], ".")) {
		n = 3
	}
	if len(labels) <= n {
		return domain, ""
	}
	return strings.Join(labels[len(labels)-n:], "."), strings.Join(labels[:len(labels)-n], ".")
}

// entropy devolve a entropia de Shannon do texto, em bits por caractere.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
