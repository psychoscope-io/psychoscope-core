package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Paineis da tela: moldura generica e os conteudos de modulos e alertas.

func panel(title string, focused bool, lines []string, w, h int) string {
	border := lipgloss.Color("240")
	if focused {
		border = lipgloss.Color("#B48EFF")
	}
	inner := max(w-2, 1)
	rows := make([]string, 0, h)
	t := " " + title + " "
	top := "╭" + t + strings.Repeat("─", max(inner-lipgloss.Width(t), 0)) + "╮"
	rows = append(rows, lipgloss.NewStyle().Foreground(border).Render(fit(top, w)))
	bar := lipgloss.NewStyle().Foreground(border).Render("│")
	for i := 0; i < h-2; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		rows = append(rows, bar+fit(line, inner)+bar)
	}
	rows = append(rows, lipgloss.NewStyle().Foreground(border).Render("╰"+strings.Repeat("─", inner)+"╯"))
	return strings.Join(rows, "\n")
}

func (m *Model) modulesPanel(w, h int) string {
	lines := []string{headerStyle.Render(fmt.Sprintf(" %-18s %-12s %7s %5s %9s %9s %8s  %-8s", "MÓDULO", "ESTADO", "PID", "REIN.", "EVENTOS", "PACOTES", "DESCART.", "CONTATO"))}
	if len(m.mods) == 0 {
		msg := "nenhum módulo configurado"
		if m.modsErr != nil {
			msg = "não foi possível consultar o core: " + m.modsErr.Error()
		}
		lines = append(lines, dimStyle.Render(" "+msg))
	}
	for i, mod := range m.mods {
		st := mod.UltimoStatus
		contato := "-"
		if mod.UltimoContato != nil {
			contato = mod.UltimoContato.AsTime().Local().Format(time.TimeOnly)
		}
		state := stateStyle(mod.Estado).Render(fmt.Sprintf("%-12s", stateName(mod.Estado)))
		row := fmt.Sprintf(" %-18s %s %7d %5d %9d %9d %8d  %-8s",
			trunc(mod.IdModulo, 18), state, mod.Pid, mod.Reinicios,
			st.GetEventosProcessados(), st.GetPacotesCapturados(), st.GetPacotesDescartados(), contato)
		if i == m.selected && m.focus == focusModules {
			row = selStyle.Render(ansi.Strip(row))
		} else if i == m.selected {
			row = lipgloss.NewStyle().Bold(true).Render(row)
		}
		lines = append(lines, row)
		if i == m.selected {
			if l := lossLine(st); l != "" {
				lines = append(lines, errStyle.Render("   "+l))
			}
			if mod.UltimoErro != "" {
				lines = append(lines, errStyle.Render("   último erro: "+mod.UltimoErro))
			}
		}
	}
	return panel("Módulos", m.focus == focusModules, lines, w, h)
}

// lossLine resume as perdas do modulo ("Perdas no kernel: 12 · ..."); vazio se nao houve nenhuma.
func lossLine(st *psychoscopev1.StatusModulo) string {
	var parts []string
	for _, c := range ctl.Losses(st) {
		parts = append(parts, fmt.Sprintf("%s: %d", c.Label, c.Value))
	}
	return strings.Join(parts, " · ")
}

func (m *Model) alertsPanel(w, h int) string {
	title := fmt.Sprintf("Alertas (%d)", len(m.alerts))
	capacity := max(h-2, 1)
	var lines []string
	if len(m.alerts) == 0 {
		lines = append(lines, dimStyle.Render(" nenhum alerta — o tráfego monitorado não disparou regras"))
		return panel(title, m.focus == focusAlerts, lines, w, h)
	}

	detail := ""
	if m.focus == focusAlerts {
		detail = contextLine(m.alerts[m.alertSel])
		capacity = max(capacity-1, 1)
	}
	start := 0
	if m.alertSel >= capacity {
		start = m.alertSel - capacity + 1
	}
	for i := start; i < len(m.alerts) && len(lines) < capacity; i++ {
		a := m.alerts[i]
		ts := "--:--:--"
		if a.Timestamp != nil {
			ts = a.Timestamp.AsTime().Local().Format(time.TimeOnly)
		}
		sev := sevStyle(a.Severidade).Render(fmt.Sprintf("%-7s", sevName(a.Severidade)))
		row := fmt.Sprintf(" %s %s %-24s %s", ts, sev, trunc(a.Regra, 24), a.Descricao)
		if i == m.alertSel && m.focus == focusAlerts {
			row = selStyle.Render(ansi.Strip(row))
		}
		lines = append(lines, row)
	}
	if detail != "" {
		lines = append(lines, dimStyle.Render(" "+detail))
	}
	return panel(title, m.focus == focusAlerts, lines, w, h)
}

func contextLine(a *psychoscopev1.Alerta) string {
	keys := make([]string, 0, len(a.Contexto))
	for k := range a.Contexto {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+a.Contexto[k])
	}
	return strings.Join(parts, " ")
}

func trunc(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
