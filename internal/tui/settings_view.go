package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Desenho da tela de configuracoes.

var draftStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))

const (
	colKey     = 24
	colValue   = 28
	colDefault = 22
	colOrigin  = 8
)

// settingsRow e uma linha da lista: o cabecalho de uma secao (field = -1) ou um campo.
type settingsRow struct {
	field   int
	section string
}

// settingsRows agrupa os campos por secao (o caminho sem a ultima parte), em ordem.
func (m *Model) settingsRows() []settingsRow {
	var rows []settingsRow
	last := ""
	for i, f := range m.cfg.fields() {
		if sec := sectionOf(f.Caminho); sec != last {
			rows = append(rows, settingsRow{field: -1, section: sec})
			last = sec
		}
		rows = append(rows, settingsRow{field: i})
	}
	return rows
}

func sectionOf(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[:i]
	}
	return path
}

func keyOf(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

// settingsCapacity e quantas linhas da lista cabem na moldura (descontando cabecalho e rodape
// da tela, a moldura e as duas linhas de descricao do campo selecionado).
func (m *Model) settingsCapacity() int { return max(max(m.height, 12)-2-2-2, 1) }

// ensureVisible ajusta a rolagem para que o campo selecionado (e o cabecalho da sua secao,
// quando e o primeiro) fique na janela de capacity linhas.
func (s *settingsState) ensureVisible(rows []settingsRow, capacity int) {
	idx := 0
	for i, r := range rows {
		if r.field == s.sel {
			idx = i
		}
	}
	top := idx
	if idx > 0 && rows[idx-1].field == -1 {
		top = idx - 1 // mostra o cabecalho da secao junto com o primeiro campo dela
	}
	switch {
	case top < s.scroll:
		s.scroll = top
	case idx >= s.scroll+capacity:
		s.scroll = idx - capacity + 1
	}
	s.scroll = clamp(s.scroll, 0, max(len(rows)-capacity, 0))
}

func (m *Model) settingsPanel(w, h int) string {
	s := m.cfg
	title := "Configurações"
	if s.readOnly() {
		title += " · somente leitura"
	}
	if n := s.pending(); n > 0 {
		title += fmt.Sprintf(" · %d alteração(ões) não gravada(s)", n)
	}
	if s.list == nil {
		return panel(title, true, []string{dimStyle.Render(" carregando…")}, w, h)
	}

	rows := m.settingsRows()
	capacity := max(h-2-2, 1) // moldura e duas linhas de descricao
	s.ensureVisible(rows, capacity)
	lines := make([]string, 0, h)
	for i := s.scroll; i < len(rows) && len(lines) < capacity; i++ {
		lines = append(lines, m.settingsRowText(rows[i]))
	}
	for len(lines) < capacity {
		lines = append(lines, "")
	}
	lines = append(lines, m.settingsDescription()...)
	return panel(title, true, lines, w, h)
}

// settingsRowText desenha uma linha da lista; o campo selecionado fica em video reverso.
func (m *Model) settingsRowText(r settingsRow) string {
	s := m.cfg
	if r.field < 0 {
		return headerStyle.Render(" " + r.section)
	}
	f := s.fields()[r.field]
	value, drafted := m.settingsValue(f)
	origin := originLabel(f.Origem)
	plainRow := fmt.Sprintf("   %-*s %-*s %-*s %-*s", colKey, trunc(keyOf(f.Caminho), colKey),
		colValue, trunc(value, colValue), colDefault, trunc(shownValue(f, f.ValorPadrao), colDefault), colOrigin, origin)
	if r.field == s.sel {
		return selStyle.Render(plainRow)
	}
	if drafted {
		return fmt.Sprintf("   %-*s %s %-*s %-*s", colKey, trunc(keyOf(f.Caminho), colKey),
			draftStyle.Render(fmt.Sprintf("%-*s", colValue, trunc(value, colValue))),
			colDefault, trunc(shownValue(f, f.ValorPadrao), colDefault), colOrigin, origin)
	}
	return plainRow
}

// settingsValue e o valor a mostrar: o do rascunho (marcado com *), "(restaurar)" ou o atual.
func (m *Model) settingsValue(f *psychoscopev1.CampoConfig) (string, bool) {
	s := m.cfg
	if d, ok := s.draft[f.Caminho]; ok {
		return shownValue(f, d) + " *", true
	}
	if s.restore[f.Caminho] {
		return "(restaurar ao valor base) *", true
	}
	return shownValue(f, f.ValorAtual), false
}

// settingsDescription sao as duas linhas sob a lista: o que o campo faz e o formato do valor.
func (m *Model) settingsDescription() []string {
	f := m.cfg.selected()
	if f == nil {
		return []string{"", ""}
	}
	return []string{" " + f.Descricao, dimStyle.Render(" " + f.Caminho + " · " + typeHint(f.Tipo))}
}

func typeHint(t psychoscopev1.TipoCampo) string {
	switch t {
	case psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO:
		return "número inteiro"
	case psychoscopev1.TipoCampo_TIPO_CAMPO_DECIMAL:
		return "número (por exemplo 0.2)"
	case psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO:
		return "duração (por exemplo 30s, 2m, 1h)"
	case psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO:
		return "lista separada por vírgula (vazia = nenhum item)"
	case psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO:
		return "números inteiros separados por vírgula (vazia = nenhum)"
	}
	return ""
}

func originLabel(o psychoscopev1.OrigemCampo) string {
	switch o {
	case psychoscopev1.OrigemCampo_ORIGEM_CAMPO_PADRAO:
		return "padrão"
	case psychoscopev1.OrigemCampo_ORIGEM_CAMPO_ARQUIVO:
		return "arquivo"
	case psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE:
		return "ajuste"
	}
	return "?"
}

// settingsFooter e o rodape da tela: a edicao em andamento ou a ajuda.
func (m *Model) settingsFooter(w int) string {
	s := m.cfg
	if s.edit != nil {
		line := fmt.Sprintf("editando %s: %s█   ", s.edit.path, s.edit.buf)
		if m.status != "" {
			// o erro de tipo vem no lugar da ajuda, sem repetir o caminho que ja esta na linha
			return fit(line+errStyle.Render(strings.TrimPrefix(m.status, s.edit.path+": ")), w)
		}
		return fit(line+dimStyle.Render("Enter confirma · Esc cancela"), w)
	}
	if s.readOnly() {
		return fit(dimStyle.Render("somente leitura · ↑/↓ navegar · :q fecha"), w)
	}
	return fit(dimStyle.Render("↑/↓ navegar · Enter edita · d restaura · :set campo=valor · :w grava · :q fecha"), w)
}
