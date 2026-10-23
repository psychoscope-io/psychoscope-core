package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// ---- view ----

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#B48EFF"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))
	selStyle    = lipgloss.NewStyle().Reverse(true)
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
)

func stateStyle(s psychoscopev1.EstadoModulo) lipgloss.Style {
	switch s {
	case psychoscopev1.EstadoModulo_ESTADO_CONECTADO:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	case psychoscopev1.EstadoModulo_ESTADO_PAUSADO:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	case psychoscopev1.EstadoModulo_ESTADO_INICIANDO, psychoscopev1.EstadoModulo_ESTADO_REINICIANDO:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	case psychoscopev1.EstadoModulo_ESTADO_FALHOU:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	}
	return dimStyle
}

func sevStyle(s psychoscopev1.Severidade) lipgloss.Style {
	switch s {
	case psychoscopev1.Severidade_SEVERIDADE_BAIXA:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	case psychoscopev1.Severidade_SEVERIDADE_MEDIA:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	case psychoscopev1.Severidade_SEVERIDADE_ALTA:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	case psychoscopev1.Severidade_SEVERIDADE_CRITICA:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("160"))
	}
	return dimStyle
}

func stateName(s psychoscopev1.EstadoModulo) string {
	return strings.TrimPrefix(s.String(), "ESTADO_")
}

func sevName(s psychoscopev1.Severidade) string {
	return strings.TrimPrefix(s.String(), "SEVERIDADE_")
}

// fit limita s a w colunas visiveis (preserva sequencias ANSI) e completa com espacos.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = ansi.Truncate(s, w, "…")
	if pad := w - lipgloss.Width(s); pad > 0 {
		s += strings.Repeat(" ", pad)
	}
	return s
}

func (m *Model) View() string {
	w, h := max(m.width, 40), max(m.height, 12)

	conn := okStyle.Render("● conectado")
	if m.modsErr != nil {
		conn = errStyle.Render("● sem conexão com o core")
	}
	stream := dimStyle.Render("alertas: reconectando")
	if m.streamOK {
		stream = dimStyle.Render("alertas: ao vivo")
	}
	line := titleStyle.Render("PSYCHOSCOPE") + dimStyle.Render(" MODR  ") + conn + dimStyle.Render("  ·  ") + stream
	if m.haveMetrics {
		line += dimStyle.Render(fmt.Sprintf("  ·  %.0f ev/s · %.0f alertas · %.0f descartes", m.evRate, m.alertsTotal, m.dropped))
	}
	header := fit(line, w)

	footer := m.footer(w)
	bodyH := h - 2 // cabecalho + rodape
	if m.detail != nil {
		return strings.Join([]string{header, m.detailPanel(w, bodyH), footer}, "\n")
	}
	modsH := min(len(m.mods)+4, max(bodyH*2/5, 5))
	alertsH := bodyH - modsH

	parts := []string{header, m.modulesPanel(w, modsH), m.alertsPanel(w, alertsH), footer}
	return strings.Join(parts, "\n")
}

func (m *Model) footer(w int) string {
	switch {
	case m.cmdline != nil:
		return fit(m.cmdlineFooter(), w)
	case m.status != "":
		st := okStyle
		if m.statusErr {
			st = errStyle
		}
		return fit(st.Render(m.status), w)
	case m.detail != nil:
		return fit(dimStyle.Render("↑/↓ rolar · PgUp/PgDn página · g/G início/fim · Esc, Enter, q ou :q fecham"), w)
	}
	return fit(dimStyle.Render("↑/↓ selecionar · tab foco · Enter detalhes · p pausar · r retomar · :q sair · :stop encerrar"), w)
}
