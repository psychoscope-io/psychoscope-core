package tui

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Linha de comando estilo vim: ':' abre, Enter executa, Esc cancela. Sair e encerrar um
// modulo exigem digitar um comando, nunca uma tecla unica que possa ser apertada por acidente.

const (
	hintQuit = "para sair: digite :q e Enter"
	hintStop = "para encerrar o módulo: digite :stop e Enter"
)

// commandNames lista os comandos aceitos, em ordem alfabetica (usada na completude com Tab).
var commandNames = []string{"pause", "q", "quit", "resume", "sair", "stop"}

// cmdline e o texto digitado depois do ':'.
type cmdline struct{ buf string }

// name devolve o primeiro termo digitado, sem espacos.
func (c *cmdline) name() string {
	f := strings.Fields(c.buf)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// actsOnModule informa se o comando digitado age no modulo selecionado.
func (c *cmdline) actsOnModule() bool {
	return slices.Contains([]string{"stop", "pause", "resume"}, c.name())
}

// complete completa o comando com o unico candidato, ou com o maior prefixo comum.
func (c *cmdline) complete() {
	if strings.ContainsAny(c.buf, " \t") {
		return
	}
	var matches []string
	for _, n := range commandNames {
		if strings.HasPrefix(n, c.buf) {
			matches = append(matches, n)
		}
	}
	if len(matches) == 0 {
		return
	}
	prefix := matches[0]
	for _, n := range matches[1:] {
		for !strings.HasPrefix(n, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	c.buf = prefix
}

func (m *Model) onKeyCmdline(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := m.cmdline
	switch k.Type {
	case tea.KeyEsc, tea.KeyCtrlC:
		m.cmdline = nil
	case tea.KeyEnter:
		m.cmdline = nil
		return m, m.runCommand(c.buf)
	case tea.KeyBackspace:
		if r := []rune(c.buf); len(r) > 0 {
			c.buf = string(r[:len(r)-1])
		}
	case tea.KeyTab:
		c.complete()
	case tea.KeySpace:
		c.buf += " "
	case tea.KeyRunes:
		c.buf += printable(k.Runes)
	}
	return m, nil
}

// printable descarta caracteres de controle (quebras de linha de texto colado, por exemplo).
func printable(rs []rune) string {
	var b strings.Builder
	for _, r := range rs {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// runCommand executa a linha digitada. Comando desconhecido nao faz nada alem de avisar.
func (m *Model) runCommand(line string) tea.Cmd {
	f := strings.Fields(line)
	if len(f) == 0 {
		return nil
	}
	if len(f) > 1 {
		return m.setStatus(fmt.Sprintf("o comando %s não aceita argumentos", f[0]), true)
	}
	switch f[0] {
	case "q", "quit", "sair":
		return m.quit()
	case "stop":
		mod := m.selectedModule()
		if mod == nil {
			return m.setStatus("nenhum módulo selecionado", true)
		}
		return tea.Batch(m.send(mod.IdModulo, psychoscopev1.ComandoControle_ENCERRAR, "encerrar "+mod.IdModulo),
			m.setStatus("encerrando "+mod.IdModulo+"…", false))
	case "pause":
		return m.moduleCommand(psychoscopev1.ComandoControle_PAUSAR, "pausar ")
	case "resume":
		return m.moduleCommand(psychoscopev1.ComandoControle_RETOMAR, "retomar ")
	}
	return m.setStatus(fmt.Sprintf("comando desconhecido: %s (use :q, :stop, :pause, :resume)", f[0]), true)
}

// moduleCommand envia acao ao modulo selecionado.
func (m *Model) moduleCommand(acao psychoscopev1.ComandoControle_TipoAcao, verb string) tea.Cmd {
	mod := m.selectedModule()
	if mod == nil {
		return m.setStatus("nenhum módulo selecionado", true)
	}
	return m.send(mod.IdModulo, acao, verb+mod.IdModulo)
}

// quit fecha o stream de alertas e encerra a TUI.
func (m *Model) quit() tea.Cmd {
	if m.stream != nil {
		m.stream.Close()
	}
	return tea.Quit
}

// cmdlineFooter e o texto do rodape enquanto o comando e digitado; mostra o modulo-alvo
// dos comandos que agem no modulo selecionado.
func (m *Model) cmdlineFooter() string {
	line := ":" + m.cmdline.buf + "█"
	if m.cmdline.actsOnModule() {
		if mod := m.selectedModule(); mod != nil {
			return line + dimStyle.Render("   → "+mod.IdModulo)
		}
		return line + errStyle.Render("   nenhum módulo selecionado")
	}
	return line
}
