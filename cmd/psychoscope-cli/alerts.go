package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// parseSince converte "90s", "15m", "2h", "7d" ou "2w" em duracao positiva.
func parseSince(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	mult := map[byte]time.Duration{'d': 24 * time.Hour, 'w': 7 * 24 * time.Hour}
	if m, ok := mult[s[len(s)-1]]; ok {
		n, err := strconv.Atoi(s[:len(s)-1])
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("--since invalido %q", s)
		}
		return time.Duration(n) * m, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--since invalido %q (exemplos: 30m, 2h, 7d)", s)
	}
	return d, nil
}

// parseSeverity aceita baixa, media, alta, critica (com ou sem acento).
func parseSeverity(s string) (psychoscopev1.Severidade, error) {
	switch strings.NewReplacer("é", "e", "í", "i").Replace(strings.ToLower(s)) {
	case "":
		return psychoscopev1.Severidade_SEVERIDADE_DESCONHECIDA, nil
	case "baixa":
		return psychoscopev1.Severidade_SEVERIDADE_BAIXA, nil
	case "media":
		return psychoscopev1.Severidade_SEVERIDADE_MEDIA, nil
	case "alta":
		return psychoscopev1.Severidade_SEVERIDADE_ALTA, nil
	case "critica":
		return psychoscopev1.Severidade_SEVERIDADE_CRITICA, nil
	}
	return 0, fmt.Errorf("--min-severity invalida %q (use baixa, media, alta ou critica)", s)
}

// formatAlert devolve a linha do alerta. Com verbose, o contexto vem logo abaixo, uma linha
// recuada "chave=valor" por chave, em ordem, e depois a tecnica ATT&CK compativel (tecnica=ID nome)
// quando a regra tem uma; sem verbose a saida e uma linha so por alerta
// (scripts, como o e2e, contam linhas).
func formatAlert(a *psychoscopev1.Alerta, verbose bool) string {
	ts := "----/--/-- --:--:--"
	if a.Timestamp != nil {
		ts = a.Timestamp.AsTime().Local().Format("2006-01-02 15:04:05")
	}
	return formatAlertAt(ts, a, verbose)
}

// formatAlertAt monta a linha do alerta com o rotulo de tempo ts ja formatado.
func formatAlertAt(ts string, a *psychoscopev1.Alerta, verbose bool) string {
	line := fmt.Sprintf("%s [%s] %s: %s", ts, strings.TrimPrefix(a.Severidade.String(), "SEVERIDADE_"), a.Regra, a.Descricao)
	if !verbose {
		return line
	}
	keys := make([]string, 0, len(a.Contexto))
	for k := range a.Contexto {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(line)
	for _, k := range keys {
		b.WriteString("\n    " + k + "=" + a.Contexto[k])
	}
	if t, ok := rules.TechniqueOf(a.Regra); ok {
		b.WriteString("\n    tecnica=" + t.String())
	}
	return b.String()
}

func cmdAlerts(ctx context.Context, cl *ctl.Client, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("alerts", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		history  = fs.Bool("history", false, "consulta o historico persistido em vez de acompanhar ao vivo")
		noHist   = fs.Bool("no-history", false, "ao vivo: nao reenvia os alertas recentes")
		limit    = fs.Int("n", 50, "maximo de alertas (com --history)")
		since    = fs.String("since", "", "so alertas dos ultimos 30m, 2h, 7d... (com --history)")
		minSev   = fs.String("min-severity", "", "baixa|media|alta|critica (com --history)")
		rule     = fs.String("rule", "", "so desta regra (com --history)")
		moduleID = fs.String("module", "", "so deste modulo (com --history)")
		verbose  = fs.Bool("v", false, "mostra o contexto (chave=valor) de cada alerta")
	)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("alerts: %w", err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("alerts: argumentos inesperados %v", fs.Args())
	}

	if !*history {
		if *since != "" || *minSev != "" || *rule != "" || *moduleID != "" {
			return errors.New("alerts: --since, --min-severity, --rule e --module exigem --history")
		}
		return streamAlerts(ctx, cl, !*noHist, *verbose, out)
	}

	d, err := parseSince(*since)
	if err != nil {
		return err
	}
	sev, err := parseSeverity(*minSev)
	if err != nil {
		return err
	}
	q := ctl.AlertQuery{Limit: *limit, MinSeverity: sev, Rule: *rule, Module: *moduleID}
	if d > 0 {
		q.Since = time.Now().Add(-d)
	}
	as, total, err := cl.Alerts(ctx, q)
	if err != nil {
		return err
	}
	for i := len(as) - 1; i >= 0; i-- { // cronologico: o mais novo por ultimo
		fmt.Fprintln(out, formatAlert(as[i], *verbose))
	}
	fmt.Fprintf(out, "-- %d de %d alertas --\n", len(as), total)
	return nil
}

func streamAlerts(ctx context.Context, cl *ctl.Client, history, verbose bool, out io.Writer) error {
	st, err := cl.StreamAlerts(ctx, history)
	if err != nil {
		return err
	}
	defer st.Close()
	for a := range st.C {
		fmt.Fprintln(out, formatAlert(a, verbose))
	}
	if ctx.Err() != nil {
		return nil
	}
	if err := st.Err(); err != nil {
		return fmt.Errorf("stream encerrado: %w", err)
	}
	return nil
}

func cmdMetrics(ctx context.Context, cl *ctl.Client, out io.Writer) error {
	ms, err := cl.Metrics(ctx)
	if err != nil {
		return err
	}
	lines := make([]string, 0, len(ms))
	for _, m := range ms {
		name := m.Nome
		if len(m.Rotulos) > 0 {
			keys := make([]string, 0, len(m.Rotulos))
			for k := range m.Rotulos {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, len(keys))
			for i, k := range keys {
				parts[i] = k + "=" + m.Rotulos[k]
			}
			name += "{" + strings.Join(parts, ",") + "}"
		}
		lines = append(lines, fmt.Sprintf("%-70s %s", name, strconv.FormatFloat(m.Valor, 'f', -1, 64)))
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Fprintln(out, l)
	}
	return nil
}
