package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Tela de detalhes de um alerta: todos os campos, com a descricao e o contexto quebrados na
// largura do terminal e rolagem vertical. Abre com Enter no painel de alertas.

const (
	detailLabelWidth = 12
	detailTimeFormat = "2006-01-02 15:04:05 -07:00"
	// eventTimeKey e a chave do contexto com o instante do evento que causou o alerta.
	eventTimeKey = "evento_ts"
)

// detail guarda o alerta exibido (o ponteiro nao muda quando chegam alertas novos) e a rolagem.
type detail struct {
	a      *psychoscopev1.Alerta
	scroll int
}

func (m *Model) onKeyDetail(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	maxScroll := m.detailMaxScroll()
	page := max(m.detailVisible()-1, 1)
	switch k.String() {
	case "esc", "enter", "q":
		m.detail = nil
		return m, nil
	case ":":
		m.cmdline = &cmdline{} // :q fecha o detalhe; :stop age no modulo selecionado
	case "i":
		return m, m.ignoreAlert()
	case "up", "k":
		m.detail.scroll--
	case "down", "j":
		m.detail.scroll++
	case "pgup":
		m.detail.scroll -= page
	case "pgdown", " ":
		m.detail.scroll += page
	case "g", "home":
		m.detail.scroll = 0
	case "G", "end":
		m.detail.scroll = maxScroll
	}
	m.detail.scroll = clamp(m.detail.scroll, 0, maxScroll)
	return m, nil
}

// detailBodyHeight e a altura da moldura do detalhe (tela menos cabecalho e rodape).
func (m *Model) detailBodyHeight() int { return max(m.height, 12) - 2 }

// detailVisible e quantas linhas de conteudo cabem dentro da moldura.
func (m *Model) detailVisible() int { return max(m.detailBodyHeight()-2, 1) }

func (m *Model) detailWidth() int { return max(m.width, 40) }

func (m *Model) detailMaxScroll() int {
	return max(len(detailLines(m.detail.a, m.detailWidth()-4))-m.detailVisible(), 0)
}

// detailPanel desenha a moldura com o alerta aberto, rolado ate d.scroll.
func (m *Model) detailPanel(w, h int) string {
	lines := detailLines(m.detail.a, w-4)
	visible := max(h-2, 1)
	start := clamp(m.detail.scroll, 0, max(len(lines)-visible, 0))
	end := min(start+visible, len(lines))
	shown := make([]string, 0, visible)
	for _, l := range lines[start:end] {
		shown = append(shown, " "+l)
	}
	title := "Alerta · " + m.detail.a.Regra
	if len(lines) > visible {
		title += fmt.Sprintf(" · linhas %d-%d de %d", start+1, end, len(lines))
	}
	return panel(title, true, shown, w, h)
}

// detailLines monta as linhas do detalhe para a largura w (area util, sem moldura).
func detailLines(a *psychoscopev1.Alerta, w int) []string {
	w = max(w, 10)
	valueW := max(w-detailLabelWidth, 5)
	field := func(label, value string) []string { return labeled(label, wrapText(value, valueW)) }

	var out []string
	out = append(out, field("Regra", a.Regra)...)
	out = append(out, labeled("Severidade", []string{sevStyle(a.Severidade).Render(sevName(a.Severidade))})...)
	out = append(out, field("Detectado", detectedAt(a))...)
	evento, hasEvent := eventTime(a)
	if hasEvent {
		out = append(out, field("Evento", evento)...)
	}
	out = append(out, field("Módulo", dash(a.IdModuloOrigem))...)
	out = append(out, field("ID", dash(a.IdAlerta))...)

	out = append(out, "", headerStyle.Render("Descrição"))
	for _, l := range wrapText(a.Descricao, w-2) {
		out = append(out, "  "+l)
	}

	if keys := contextKeys(a, hasEvent); len(keys) > 0 {
		out = append(out, "", headerStyle.Render("Contexto"))
		out = append(out, contextLines(a, keys, w)...)
	}
	if field, value, ok := rules.Exception(a); ok {
		out = append(out, "", headerStyle.Render("Ação"))
		for _, l := range wrapText("tecla i: acrescenta "+value+" a "+field+" (só root; vale na hora; a lista ajustada substitui a do arquivo do administrador)", w-2) {
			out = append(out, "  "+l)
		}
	}
	return out
}

// contextLines desenha o contexto como tabela chave/valor, com os valores quebrados na largura.
func contextLines(a *psychoscopev1.Alerta, keys []string, w int) []string {
	keyW := 0
	for _, k := range keys {
		keyW = max(keyW, len([]rune(k)))
	}
	valW := max(w-keyW-4, 5)
	var out []string
	for _, k := range keys {
		for i, l := range wrapText(a.Contexto[k], valW) {
			label := ""
			if i == 0 {
				label = k
			}
			out = append(out, fmt.Sprintf("  %-*s  %s", keyW, label, l))
		}
	}
	return out
}

// labeled escreve o rotulo na primeira linha e alinha as demais com recuo.
func labeled(label string, lines []string) []string {
	out := make([]string, 0, len(lines))
	for i, l := range lines {
		prefix := strings.Repeat(" ", detailLabelWidth)
		if i == 0 {
			prefix = headerStyle.Render(fmt.Sprintf("%-*s", detailLabelWidth, label))
		}
		out = append(out, prefix+l)
	}
	return out
}

func detectedAt(a *psychoscopev1.Alerta) string {
	if a.Timestamp == nil {
		return "-"
	}
	t := a.Timestamp.AsTime()
	return t.Local().Format(detailTimeFormat) + " (" + t.UTC().Format(time.RFC3339) + ")"
}

// eventTime formata o instante do evento guardado no contexto; ok=false se ausente ou invalido
// (nesse caso o valor continua visivel na tabela de contexto).
func eventTime(a *psychoscopev1.Alerta) (string, bool) {
	raw, ok := a.Contexto[eventTimeKey]
	if !ok {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return "", false
	}
	return t.Local().Format(detailTimeFormat) + " (" + t.UTC().Format(time.RFC3339) + ")", true
}

// contextKeys devolve as chaves do contexto em ordem; omite o instante do evento quando ele
// ja aparece como campo proprio.
func contextKeys(a *psychoscopev1.Alerta, eventShown bool) []string {
	keys := make([]string, 0, len(a.Contexto))
	for k := range a.Contexto {
		if eventShown && k == eventTimeKey {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// wrapText quebra s em linhas de no maximo w colunas. Quebra preferencialmente depois de
// espacos e virgulas (listas ficam um item por trecho) e parte ao meio so o que nao cabe
// em nenhuma linha. Sempre devolve ao menos uma linha.
func wrapText(s string, w int) []string {
	w = max(w, 1)
	var lines []string
	var cur []rune
	flush := func() {
		lines = append(lines, strings.TrimRight(string(cur), " "))
		cur = cur[:0]
	}
	for _, seg := range splitSegments(s) {
		for visibleLen(seg) > w {
			if len(cur) > 0 {
				flush()
			}
			lines = append(lines, string(seg[:w]))
			seg = seg[w:]
		}
		// o espaco que termina o trecho nao ocupa largura: some ao quebrar a linha
		if len(cur)+visibleLen(seg) > w && len(cur) > 0 {
			flush()
		}
		cur = append(cur, seg...)
	}
	if len(cur) > 0 || len(lines) == 0 {
		flush()
	}
	return lines
}

// visibleLen e o tamanho do trecho sem os espacos finais.
func visibleLen(seg []rune) int {
	n := len(seg)
	for n > 0 && seg[n-1] == ' ' {
		n--
	}
	return n
}

// splitSegments divide s em trechos que terminam em espaco ou virgula (o separador fica no trecho).
func splitSegments(s string) [][]rune {
	var segs [][]rune
	var cur []rune
	for _, r := range s {
		cur = append(cur, r)
		if r == ' ' || r == ',' {
			segs = append(segs, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		segs = append(segs, cur)
	}
	return segs
}

// ignoreAlert (tecla i) acrescenta a excecao sugerida para o alerta aberto a lista de
// configuracao da regra: o destino confiavel, o dominio conhecido. So o root grava.
func (m *Model) ignoreAlert() tea.Cmd {
	field, value, ok := rules.Exception(m.detail.a)
	if !ok {
		return m.setStatus("esta regra não tem exceção sugerida (ajuste o limiar em :config)", false)
	}
	return tea.Batch(m.ignoreCmd(field, value), m.setStatus("acrescentando "+value+"…", false))
}

func (m *Model) onIgnoreDone(msg ignoreDoneMsg) tea.Cmd {
	switch {
	case msg.err != nil:
		return m.setStatus(msg.err.Error(), true)
	case msg.already:
		return m.setStatus(msg.value+" já está em "+msg.field, false)
	}
	return m.setStatus(msg.value+" acrescentado a "+msg.field+" (vale na hora; este alerta continua no histórico)", false)
}
