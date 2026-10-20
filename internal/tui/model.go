package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

const (
	refreshEvery   = time.Second
	reconnectAfter = 2 * time.Second
	maxAlerts      = 500
	callTimeout    = 3 * time.Second
	commandTimeout = 35 * time.Second // ENCERRAR pode levar o StopGrace do modulo
	statusTTL      = 5 * time.Second
)

type focus int

const (
	focusModules focus = iota
	focusAlerts
)

// ---- mensagens ----

type (
	tickMsg    time.Time
	modulesMsg struct {
		mods []*psychoscopev1.ModuloInfo
		err  error
	}
	streamOpenedMsg struct {
		s   Stream
		err error
	}
	alertMsg        struct{ a *psychoscopev1.Alerta }
	streamClosedMsg struct{ err error }
	reopenMsg       struct{}
	commandDoneMsg  struct {
		label string
		err   error
	}
	clearStatusMsg struct{ seq int }
)

type pending struct {
	module string
	acao   psychoscopev1.ComandoControle_TipoAcao
}

// Model e o estado da TUI (tea.Model).
type Model struct {
	be Backend

	width, height int

	mods     []*psychoscopev1.ModuloInfo
	modsErr  error
	selected int // modulo selecionado

	alerts   []*psychoscopev1.Alerta // mais novo primeiro
	alertSel int
	stream   Stream
	streamOK bool

	focus   focus
	confirm *pending

	status    string
	statusErr bool
	statusSeq int
}

// NewModel cria a TUI sobre b.
func NewModel(b Backend) *Model { return &Model{be: b, width: 100, height: 30} }

// ---- comandos assincronos ----

func (m *Model) fetchModules() tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		mods, err := be.List(ctx)
		return modulesMsg{mods, err}
	}
}

func (m *Model) tick() tea.Cmd {
	return tea.Tick(refreshEvery, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) openStream() tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		// O contexto so cobre a conexao inicial; o stream vive ate Close.
		s, err := be.StreamAlerts(context.WithoutCancel(ctx))
		return streamOpenedMsg{s, err}
	}
}

func waitAlert(s Stream) tea.Cmd {
	return func() tea.Msg {
		a, ok := <-s.Alerts()
		if !ok {
			return streamClosedMsg{s.Err()}
		}
		return alertMsg{a}
	}
}

func (m *Model) send(module string, acao psychoscopev1.ComandoControle_TipoAcao, label string) tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		return commandDoneMsg{label, be.Command(ctx, module, acao)}
	}
}

func (m *Model) setStatus(text string, isErr bool) tea.Cmd {
	m.status, m.statusErr = text, isErr
	m.statusSeq++
	seq := m.statusSeq
	return tea.Tick(statusTTL, func(time.Time) tea.Msg { return clearStatusMsg{seq} })
}

// ---- tea.Model ----

func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.fetchModules(), m.openStream(), m.tick())
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tickMsg:
		return m, tea.Batch(m.fetchModules(), m.tick())

	case modulesMsg:
		m.modsErr = msg.err
		if msg.err == nil {
			m.mods = msg.mods
			sort.SliceStable(m.mods, func(i, j int) bool { return m.mods[i].IdModulo < m.mods[j].IdModulo })
			m.selected = clamp(m.selected, 0, len(m.mods)-1)
		}

	case streamOpenedMsg:
		if msg.err != nil {
			m.streamOK = false
			return m, tea.Tick(reconnectAfter, func(time.Time) tea.Msg { return reopenMsg{} })
		}
		m.stream, m.streamOK = msg.s, true
		return m, waitAlert(msg.s)

	case reopenMsg:
		return m, m.openStream()

	case alertMsg:
		m.alerts = append([]*psychoscopev1.Alerta{msg.a}, m.alerts...)
		if len(m.alerts) > maxAlerts {
			m.alerts = m.alerts[:maxAlerts]
		}
		if m.alertSel > 0 { // mantem a selecao no mesmo alerta enquanto chegam novos
			m.alertSel = clamp(m.alertSel+1, 0, len(m.alerts)-1)
		}
		return m, waitAlert(m.stream)

	case streamClosedMsg:
		m.streamOK = false
		if m.stream != nil {
			m.stream.Close()
			m.stream = nil
		}
		return m, tea.Tick(reconnectAfter, func(time.Time) tea.Msg { return reopenMsg{} })

	case commandDoneMsg:
		cmds := []tea.Cmd{m.fetchModules()}
		if msg.err != nil {
			cmds = append(cmds, m.setStatus(fmt.Sprintf("%s: %v", msg.label, msg.err), true))
		} else {
			cmds = append(cmds, m.setStatus(msg.label+": ok", false))
		}
		return m, tea.Batch(cmds...)

	case clearStatusMsg:
		if msg.seq == m.statusSeq {
			m.status = ""
		}

	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m *Model) selectedModule() *psychoscopev1.ModuloInfo {
	if m.selected < 0 || m.selected >= len(m.mods) {
		return nil
	}
	return m.mods[m.selected]
}

func (m *Model) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Confirmacao pendente: qualquer tecla responde.
	if m.confirm != nil {
		p := *m.confirm
		m.confirm = nil
		if s := k.String(); s == "y" || s == "Y" {
			return m, tea.Batch(m.send(p.module, p.acao, "encerrar "+p.module), m.setStatus("encerrando "+p.module+"…", false))
		}
		return m, m.setStatus("cancelado", false)
	}

	switch k.String() {
	case "q", "ctrl+c", "esc":
		if m.stream != nil {
			m.stream.Close()
		}
		return m, tea.Quit
	case "tab":
		m.focus = (m.focus + 1) % 2
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "g", "home":
		m.move(-1 << 30)
	case "G", "end":
		m.move(1 << 30)
	case "p", "r":
		mod := m.selectedModule()
		if mod == nil {
			return m, m.setStatus("nenhum módulo selecionado", true)
		}
		acao, label := psychoscopev1.ComandoControle_PAUSAR, "pausar "
		if k.String() == "r" {
			acao, label = psychoscopev1.ComandoControle_RETOMAR, "retomar "
		}
		return m, m.send(mod.IdModulo, acao, label+mod.IdModulo)
	case "x":
		mod := m.selectedModule()
		if mod == nil {
			return m, m.setStatus("nenhum módulo selecionado", true)
		}
		m.confirm = &pending{mod.IdModulo, psychoscopev1.ComandoControle_ENCERRAR}
	}
	return m, nil
}

func (m *Model) move(delta int) {
	if m.focus == focusModules {
		m.selected = clamp(m.selected+delta, 0, len(m.mods)-1)
	} else {
		m.alertSel = clamp(m.alertSel+delta, 0, len(m.alerts)-1)
	}
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	return max(lo, min(v, hi))
}

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
	header := fit(titleStyle.Render("PSYCHOSCOPE")+dimStyle.Render(" MODR  ")+conn+dimStyle.Render("  ·  ")+stream, w)

	footer := m.footer(w)
	bodyH := h - 2 // cabecalho + rodape
	modsH := min(len(m.mods)+4, max(bodyH*2/5, 5))
	alertsH := bodyH - modsH

	parts := []string{header, m.modulesPanel(w, modsH), m.alertsPanel(w, alertsH), footer}
	return strings.Join(parts, "\n")
}

func (m *Model) footer(w int) string {
	switch {
	case m.confirm != nil:
		return fit(errStyle.Render(fmt.Sprintf("Encerrar %q? (y/n)", m.confirm.module)), w)
	case m.status != "":
		st := okStyle
		if m.statusErr {
			st = errStyle
		}
		return fit(st.Render(m.status), w)
	}
	return fit(dimStyle.Render("↑/↓ selecionar · tab foco · p pausar · r retomar · x encerrar · q sair"), w)
}

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
		if mod.UltimoErro != "" && i == m.selected {
			lines = append(lines, errStyle.Render("   último erro: "+mod.UltimoErro))
		}
	}
	return panel("Módulos", m.focus == focusModules, lines, w, h)
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
