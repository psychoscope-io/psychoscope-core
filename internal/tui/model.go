package tui

import (
	"fmt"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

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

	// metricas do Core (taxa calculada entre duas consultas)
	haveMetrics bool
	prevEvents  float64
	prevAt      time.Time
	evRate      float64
	alertsTotal float64
	dropped     float64
}

// NewModel cria a TUI sobre b.
func NewModel(b Backend) *Model { return &Model{be: b, width: 100, height: 30} }

// Init dispara a primeira leitura de modulos, metricas e o stream de alertas.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.fetchModules(), m.fetchMetrics(), m.openStream(), m.tick())
}

// Update trata uma mensagem. Cada caso delega a um metodo pequeno.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		return m, tea.Batch(m.fetchModules(), m.fetchMetrics(), m.tick())
	case modulesMsg:
		m.onModules(msg)
	case metricsMsg:
		m.onMetrics(msg)
	case streamOpenedMsg:
		return m, m.onStreamOpened(msg)
	case reopenMsg:
		return m, m.openStream()
	case alertMsg:
		return m, m.onAlert(msg)
	case streamClosedMsg:
		return m, m.onStreamClosed()
	case commandDoneMsg:
		return m, m.onCommandDone(msg)
	case clearStatusMsg:
		if msg.seq == m.statusSeq {
			m.status = ""
		}
	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m *Model) onModules(msg modulesMsg) {
	m.modsErr = msg.err
	if msg.err != nil {
		return
	}
	m.mods = msg.mods
	sort.SliceStable(m.mods, func(i, j int) bool { return m.mods[i].IdModulo < m.mods[j].IdModulo })
	m.selected = clamp(m.selected, 0, len(m.mods)-1)
}

func (m *Model) onMetrics(msg metricsMsg) {
	if msg.err != nil {
		m.haveMetrics = false
		return
	}
	m.applyMetrics(msg.ms, msg.at)
}

func reopenAfter() tea.Cmd {
	return tea.Tick(reconnectAfter, func(time.Time) tea.Msg { return reopenMsg{} })
}

func (m *Model) onStreamOpened(msg streamOpenedMsg) tea.Cmd {
	if msg.err != nil {
		m.streamOK = false
		return reopenAfter()
	}
	m.stream, m.streamOK = msg.s, true
	return waitAlert(msg.s)
}

// onAlert insere o alerta no topo (mais novo primeiro), respeita o limite e mantem
// a selecao no mesmo alerta enquanto chegam novos.
func (m *Model) onAlert(msg alertMsg) tea.Cmd {
	m.alerts = append([]*psychoscopev1.Alerta{msg.a}, m.alerts...)
	if len(m.alerts) > maxAlerts {
		m.alerts = m.alerts[:maxAlerts]
	}
	if m.alertSel > 0 {
		m.alertSel = clamp(m.alertSel+1, 0, len(m.alerts)-1)
	}
	return waitAlert(m.stream)
}

func (m *Model) onStreamClosed() tea.Cmd {
	m.streamOK = false
	if m.stream != nil {
		m.stream.Close()
		m.stream = nil
	}
	return reopenAfter()
}

func (m *Model) onCommandDone(msg commandDoneMsg) tea.Cmd {
	var status tea.Cmd
	if msg.err != nil {
		status = m.setStatus(fmt.Sprintf("%s: %v", msg.label, msg.err), true)
	} else {
		status = m.setStatus(msg.label+": ok", false)
	}
	return tea.Batch(m.fetchModules(), status)
}

func (m *Model) applyMetrics(ms []*psychoscopev1.Metrica, at time.Time) {
	var events, dropped, alerts float64
	for _, x := range ms {
		switch x.Nome {
		case "psychoscope_engine_events_processed_total":
			events = x.Valor
		case "psychoscope_engine_events_dropped_total", "psychoscope_module_packets_dropped_total":
			dropped += x.Valor
		case "psychoscope_engine_alerts_total":
			alerts = x.Valor
		}
	}
	m.evRate = 0
	if m.haveMetrics && events >= m.prevEvents {
		if dt := at.Sub(m.prevAt).Seconds(); dt > 0 {
			m.evRate = (events - m.prevEvents) / dt
		}
	}
	m.haveMetrics, m.prevEvents, m.prevAt = true, events, at
	m.dropped, m.alertsTotal = dropped, alerts
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
