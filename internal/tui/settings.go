package tui

import (
	"fmt"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Tela de configuracoes: lista os campos editaveis do Core (valor atual, padrao e origem),
// edita por Enter ou por :set, junta as alteracoes num rascunho e grava tudo de uma vez com
// :w (a validacao do Core e conjunta). So o root grava; os demais veem a tela em modo leitura.

// settingsState e o estado da tela de configuracoes.
type settingsState struct {
	list    *psychoscopev1.ListaConfig // ultima leitura; nil enquanto carrega
	sel     int                        // indice do campo selecionado em list.Campos
	scroll  int                        // primeira linha visivel (cabecalhos de secao contam)
	draft   map[string]string          // caminho -> valor JSON ainda nao gravado
	restore map[string]bool            // caminhos a restaurar ao valor base
	edit    *fieldEdit                 // edicao em andamento, ou nil
}

// fieldEdit e a edicao de um valor pelo Enter.
type fieldEdit struct {
	path string
	lineEditor
}

func newSettingsState() *settingsState {
	return &settingsState{draft: map[string]string{}, restore: map[string]bool{}}
}

func (s *settingsState) fields() []*psychoscopev1.CampoConfig { return s.list.GetCampos() }

func (s *settingsState) readOnly() bool { return s.list.GetSomenteLeitura() }

// pending conta as alteracoes ainda nao gravadas.
func (s *settingsState) pending() int { return len(s.draft) + len(s.restore) }

func (s *settingsState) selected() *psychoscopev1.CampoConfig {
	if s.sel < 0 || s.sel >= len(s.fields()) {
		return nil
	}
	return s.fields()[s.sel]
}

// selectField move a selecao para o campo f.
func (s *settingsState) selectField(f *psychoscopev1.CampoConfig) {
	if i := slices.Index(s.fields(), f); i >= 0 {
		s.sel = i
	}
}

func (s *settingsState) find(path string) *psychoscopev1.CampoConfig {
	for _, f := range s.fields() {
		if f.Caminho == path {
			return f
		}
	}
	return nil
}

// stage poe o valor (JSON) de um campo no rascunho; valor igual ao atual desfaz o rascunho.
func (s *settingsState) stage(f *psychoscopev1.CampoConfig, jsonValue string) {
	delete(s.restore, f.Caminho)
	if jsonValue == f.ValorAtual {
		delete(s.draft, f.Caminho)
		return
	}
	s.draft[f.Caminho] = jsonValue
}

// markRestore marca o campo para voltar ao valor base. Sem ajuste gravado nem rascunho nao ha o que restaurar.
func (s *settingsState) markRestore(f *psychoscopev1.CampoConfig) bool {
	delete(s.draft, f.Caminho)
	if f.Origem != psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE {
		delete(s.restore, f.Caminho)
		return false
	}
	s.restore[f.Caminho] = true
	return true
}

// ---- abrir, ler e gravar ----

// openSettings abre a tela e le a configuracao; com a tela ja aberta, apenas le de novo
// (o rascunho e mantido).
func (m *Model) openSettings() tea.Cmd {
	m.detail = nil
	if m.cfg == nil {
		m.cfg = newSettingsState()
	}
	return m.fetchConfig()
}

func (m *Model) onConfig(msg configMsg) tea.Cmd {
	if m.cfg == nil {
		return nil
	}
	if msg.err != nil {
		if m.cfg.list == nil { // nunca abriu: volta a tela principal
			m.cfg = nil
		}
		return m.setStatus("configuração: "+msg.err.Error(), true)
	}
	m.cfg.list = msg.list
	m.cfg.sel = clamp(m.cfg.sel, 0, len(m.cfg.fields())-1)
	return nil
}

func (m *Model) onConfigApplied(msg configAppliedMsg) tea.Cmd {
	if m.cfg == nil {
		return nil
	}
	if msg.err != nil { // o rascunho fica: a mensagem do Core diz qual campo corrigir
		return m.setStatus(msg.err.Error(), true)
	}
	m.cfg.list = msg.list
	m.cfg.draft, m.cfg.restore = map[string]string{}, map[string]bool{}
	m.cfg.sel = clamp(m.cfg.sel, 0, len(m.cfg.fields())-1)
	text := fmt.Sprintf("configuração aplicada (%d campo(s))", msg.changes)
	if w := msg.list.GetAvisos(); len(w) > 0 {
		text += ": " + strings.Join(w, "; ")
	}
	cmd := m.setStatus(text, len(msg.list.GetAvisos()) > 0)
	if msg.closeAfter {
		m.cfg = nil
	}
	return cmd
}

// ---- teclas ----

func (m *Model) onKeySettings(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := m.cfg
	if s.edit != nil {
		return m.onKeyFieldEdit(k)
	}
	page := max(m.settingsCapacity()-1, 1)
	switch k.String() {
	case ":":
		m.cmdline = &cmdline{}
	case "up", "k":
		s.move(-1)
	case "down", "j":
		s.move(1)
	case "pgup":
		s.move(-page)
	case "pgdown", " ":
		s.move(page)
	case "g", "home":
		s.move(-1 << 30)
	case "G", "end":
		s.move(1 << 30)
	case "enter":
		return m, m.startFieldEdit()
	case "d":
		return m, m.restoreSelected()
	case "q", "esc", "ctrl+c":
		return m, m.setStatus("para fechar a tela: :q (ou :q! para descartar as alterações)", false)
	}
	return m, nil
}

func (s *settingsState) move(delta int) {
	s.sel = clamp(s.sel+delta, 0, len(s.fields())-1)
}

// startFieldEdit abre o editor de linha no campo selecionado, ja com o valor (rascunho ou atual).
func (m *Model) startFieldEdit() tea.Cmd {
	s := m.cfg
	f := s.selected()
	if f == nil {
		return nil
	}
	if s.readOnly() {
		return m.setStatus(readOnlyMsg, true)
	}
	value := f.ValorAtual
	if d, ok := s.draft[f.Caminho]; ok {
		value = d
	}
	s.edit = &fieldEdit{path: f.Caminho, lineEditor: lineEditor{buf: ctl.TextFromValue(f, value)}}
	return nil
}

func (m *Model) onKeyFieldEdit(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := m.cfg
	switch k.Type {
	case tea.KeyEsc, tea.KeyCtrlC:
		s.edit = nil
	case tea.KeyEnter:
		f := s.find(s.edit.path)
		text := s.edit.buf
		if f == nil {
			s.edit = nil
			return m, nil
		}
		v, err := ctl.ValueFromText(f, text)
		if err != nil { // continua editando: a pessoa corrige o texto
			return m, m.setStatus(err.Error(), true)
		}
		s.edit = nil
		s.stage(f, v)
	default:
		s.edit.edit(k)
	}
	return m, nil
}

// restoreSelected marca o campo selecionado para voltar ao valor base (tecla d).
func (m *Model) restoreSelected() tea.Cmd {
	s := m.cfg
	f := s.selected()
	if f == nil {
		return nil
	}
	if s.readOnly() {
		return m.setStatus(readOnlyMsg, true)
	}
	if !s.markRestore(f) {
		return m.setStatus(f.Caminho+" ja esta no valor base (sem ajuste gravado)", false)
	}
	return nil
}

const readOnlyMsg = "somente leitura: abra a TUI como root (sudo psychoscope-cli) para alterar"

// ---- comandos da tela (tabela commands) ----

func (m *Model) cmdConfig(args []string) tea.Cmd {
	if len(args) > 0 {
		return m.argsError("config")
	}
	return m.openSettings()
}

// needSettings recusa um comando que so vale com a tela de configuracoes aberta.
func (m *Model) needSettings(name string) tea.Cmd {
	return m.setStatus(fmt.Sprintf(":%s vale na tela de configurações (abra com :config)", name), true)
}

func (m *Model) cmdWrite(args []string) tea.Cmd { return m.write(args, "w", false) }

func (m *Model) cmdWriteQuit(args []string) tea.Cmd { return m.write(args, "wq", true) }

func (m *Model) write(args []string, name string, closeAfter bool) tea.Cmd {
	if len(args) > 0 {
		return m.argsError(name)
	}
	s := m.cfg
	if s == nil {
		return m.needSettings(name)
	}
	if s.readOnly() {
		return m.setStatus(readOnlyMsg, true)
	}
	if s.pending() == 0 {
		if closeAfter {
			m.cfg = nil
			return nil
		}
		return m.setStatus("nada a gravar", false)
	}
	restore := make([]string, 0, len(s.restore))
	for p := range s.restore {
		restore = append(restore, p)
	}
	slices.Sort(restore)
	patch := make(map[string]string, len(s.draft))
	for p, v := range s.draft {
		patch[p] = v
	}
	return tea.Batch(m.applyConfig(patch, restore, closeAfter), m.setStatus("gravando…", false))
}

// cmdSet: ":set campo=valor" poe no rascunho, ":set campo&" restaura ao valor base e
// ":set campo" mostra o valor, como o :set do vim.
func (m *Model) cmdSet(args []string) tea.Cmd {
	s := m.cfg
	if s == nil {
		return m.needSettings("set")
	}
	if len(args) == 0 {
		return m.setStatus("uso: :set campo=valor | :set campo& (restaura) | :set campo (mostra)", true)
	}
	line := strings.Join(args, " ") // o valor pode ter espacos (listas)
	path, text, hasValue := strings.Cut(line, "=")
	path = strings.TrimSpace(path)
	restoreIt := strings.HasSuffix(path, "&") && !hasValue
	path = strings.TrimSuffix(path, "&")
	f := s.find(path)
	if f == nil {
		return m.setStatus(fmt.Sprintf("campo desconhecido ou não editável: %q (Tab completa)", path), true)
	}
	s.selectField(f) // leva a selecao ao campo, como o :set do vim: a mudanca fica a vista
	switch {
	case restoreIt:
		if s.readOnly() {
			return m.setStatus(readOnlyMsg, true)
		}
		if !s.markRestore(f) {
			return m.setStatus(f.Caminho+" ja esta no valor base (sem ajuste gravado)", false)
		}
		return nil
	case !hasValue:
		value := f.ValorAtual
		if d, ok := s.draft[f.Caminho]; ok {
			value = d
		}
		return m.setStatus(fmt.Sprintf("%s = %s  (padrão: %s)", f.Caminho, shownValue(f, value), shownValue(f, f.ValorPadrao)), false)
	}
	if s.readOnly() {
		return m.setStatus(readOnlyMsg, true)
	}
	v, err := ctl.ValueFromText(f, text)
	if err != nil {
		return m.setStatus(err.Error(), true)
	}
	s.stage(f, v)
	return nil
}

// closeSettings fecha a tela; sem force, o :q: recusa fechar com alteracoes nao gravadas.
func (m *Model) closeSettings(force bool) tea.Cmd {
	if n := m.cfg.pending(); n > 0 && !force {
		return m.setStatus(fmt.Sprintf("%d alteração(ões) não gravada(s): :w grava, :q! descarta", n), true)
	}
	m.cfg = nil
	return nil
}

// completeSetPath completa o caminho do campo digitado depois de ":set ".
func (m *Model) completeSetPath(c *cmdline) {
	if m.cfg == nil || m.cfg.list == nil {
		return
	}
	head, typed, ok := strings.Cut(c.buf, " ")
	if !ok || head != "set" || strings.Contains(typed, "=") {
		return
	}
	var matches []string
	for _, f := range m.cfg.fields() {
		if strings.HasPrefix(f.Caminho, typed) {
			matches = append(matches, f.Caminho)
		}
	}
	if len(matches) == 0 {
		return
	}
	prefix := matches[0]
	for _, p := range matches[1:] {
		for !strings.HasPrefix(p, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	c.buf = "set " + prefix
}

// shownValue mostra um valor JSON como se digitaria; lista vazia aparece como [].
func shownValue(f *psychoscopev1.CampoConfig, jsonValue string) string {
	if t := ctl.TextFromValue(f, jsonValue); t != "" {
		return t
	}
	return "[]"
}
