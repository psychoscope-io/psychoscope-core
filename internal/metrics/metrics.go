// Package metrics monta o instantaneo de metricas do Core e o expoe no formato texto do
// Prometheus (versao 0.0.4), sem dependencias externas. As metricas usam a mesma
// mensagem do canal de controle (psychoscopev1.Metrica).
package metrics

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Gatherer produz um conjunto de metricas.
type Gatherer func() []*psychoscopev1.Metrica

// Counter cria uma metrica monotonica. labels e uma lista chave, valor, chave, valor...
func Counter(name, help string, v float64, labels ...string) *psychoscopev1.Metrica {
	return metric(psychoscopev1.TipoMetrica_TIPO_METRICA_CONTADOR, name, help, v, labels)
}

// Gauge cria uma metrica instantanea.
func Gauge(name, help string, v float64, labels ...string) *psychoscopev1.Metrica {
	return metric(psychoscopev1.TipoMetrica_TIPO_METRICA_MEDIDOR, name, help, v, labels)
}

func metric(t psychoscopev1.TipoMetrica, name, help string, v float64, labels []string) *psychoscopev1.Metrica {
	m := &psychoscopev1.Metrica{Nome: name, Tipo: t, Ajuda: help, Valor: v}
	if len(labels) >= 2 {
		m.Rotulos = make(map[string]string, len(labels)/2)
		for i := 0; i+1 < len(labels); i += 2 {
			m.Rotulos[labels[i]] = labels[i+1]
		}
	}
	return m
}

// Gather junta as saidas dos coletores em ordem estavel (nome, depois rotulos).
func Gather(gs ...Gatherer) []*psychoscopev1.Metrica {
	var all []*psychoscopev1.Metrica
	for _, g := range gs {
		if g != nil {
			all = append(all, g()...)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Nome != all[j].Nome {
			return all[i].Nome < all[j].Nome
		}
		return labelString(all[i].Rotulos) < labelString(all[j].Rotulos)
	})
	return all
}

func sanitizeName(s string, allowColon bool) string {
	var b strings.Builder
	for i, r := range s {
		ok := r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (allowColon && r == ':') || (i > 0 && r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	valueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
)

func labelString(l map[string]string) string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = sanitizeName(k, false) + `="` + valueEscaper.Replace(l[k]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// WriteText escreve ms no formato de exposicao do Prometheus. ms deve estar ordenado
// por nome (use Gather); HELP/TYPE saem uma vez por nome.
func WriteText(w io.Writer, ms []*psychoscopev1.Metrica) error {
	last := ""
	for _, m := range ms {
		name := sanitizeName(m.Nome, true)
		if name != last {
			last = name
			typ := "gauge"
			if m.Tipo == psychoscopev1.TipoMetrica_TIPO_METRICA_CONTADOR {
				typ = "counter"
			}
			if m.Ajuda != "" {
				if _, err := fmt.Fprintf(w, "# HELP %s %s\n", name, helpEscaper.Replace(m.Ajuda)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", name, typ); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s%s %s\n", name, labelString(m.Rotulos), formatValue(m.Valor)); err != nil {
			return err
		}
	}
	return nil
}

// Handler serve GET /metrics com o resultado de g. Qualquer outro metodo ou caminho e recusado.
func Handler(g func() []*psychoscopev1.Metrica) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "metodo nao permitido", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		_ = WriteText(w, g())
	})
	return mux
}

// Listen abre o listener TCP do endpoint (separado de Serve para que erros de bind
// aparecam na partida e testes possam usar a porta 0).
func Listen(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// Serve atende h em ln ate ctx ser cancelado, com timeouts curtos.
func Serve(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		<-errc //nolint:errcheck // so espera o servidor parar
		return nil
	case err := <-errc:
		return err
	}
}
